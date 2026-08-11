use std::{
    fmt, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use bytes::Bytes;
use futures_util::Stream;
use multer::{Constraints, Multipart, SizeLimit};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};

use crate::outbound::{SendRequest, StreamingAttachmentInput};

const MAX_DATA_BYTES: usize = 64 * 1024;
const MAX_MULTIPART_FILES: usize = 256;
const CREATE_ATTEMPTS: usize = 16;

#[derive(Debug)]
pub(crate) enum WebMultipartError {
    Invalid,
    AttachmentTooLarge(String),
    AttachmentsTooLarge,
    Unavailable,
}

impl fmt::Display for WebMultipartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("invalid multipart request"),
            Self::AttachmentTooLarge(filename) => {
                write!(formatter, "attachment is too large: {filename}")
            }
            Self::AttachmentsTooLarge => formatter.write_str("attachments are too large"),
            Self::Unavailable => formatter.write_str("multipart storage is unavailable"),
        }
    }
}

impl std::error::Error for WebMultipartError {}

#[derive(Debug)]
struct OwnedUpload {
    filename: String,
    content_type: Option<String>,
    path: PathBuf,
    size: u64,
}

impl Drop for OwnedUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Debug)]
pub(crate) struct ParsedWebMultipart {
    request: Option<SendRequest>,
    uploads: Vec<OwnedUpload>,
}

impl ParsedWebMultipart {
    pub(crate) fn take_request(&mut self) -> SendRequest {
        self.request
            .take()
            .expect("multipart request may only be consumed once")
    }

    pub(crate) fn attachment_inputs(&self) -> Vec<StreamingAttachmentInput> {
        self.uploads
            .iter()
            .map(|upload| StreamingAttachmentInput {
                filename: upload.filename.clone(),
                content_type: upload.content_type.clone(),
                path: upload.path.clone(),
                size: upload.size,
            })
            .collect()
    }
}

pub(crate) fn boundary(content_type: &str) -> Result<String, WebMultipartError> {
    multer::parse_boundary(content_type).map_err(|_| WebMultipartError::Invalid)
}

pub(crate) async fn parse<S>(
    stream: S,
    boundary: String,
    upload_root: &Path,
    max_stream_bytes: u64,
    max_attachment_bytes: u64,
    max_total_attachment_bytes: u64,
) -> Result<ParsedWebMultipart, WebMultipartError>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send,
{
    let constraints =
        Constraints::new().size_limit(SizeLimit::new().whole_stream(max_stream_bytes));
    let mut multipart = Multipart::with_constraints(stream, boundary, constraints);
    let upload_root = secure_upload_directory(upload_root).await?;
    let mut data = None;
    let mut uploads = Vec::new();
    let mut total_attachment_bytes = 0_u64;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| WebMultipartError::Invalid)?
    {
        let name = field.name().unwrap_or_default().to_owned();
        let filename = field.file_name().map(str::to_owned);
        let content_type = field.content_type().map(ToString::to_string);
        if name == "data" && is_possible_data_field(filename.as_deref(), content_type.as_deref()) {
            let bytes = read_bounded_field(&mut field, MAX_DATA_BYTES + 1).await?;
            if bytes.len() <= MAX_DATA_BYTES
                && is_data_field(filename.as_deref(), content_type.as_deref(), bytes.len())
            {
                data = Some(bytes);
            }
            continue;
        }
        if name != "attachments" || filename.is_none() {
            drain_bounded_field(&mut field, max_attachment_bytes).await?;
            continue;
        }
        if uploads.len() >= MAX_MULTIPART_FILES {
            return Err(WebMultipartError::Invalid);
        }
        let filename = filename.unwrap_or_default();
        let (path, mut output) = create_upload(&upload_root).await?;
        let mut size = 0_u64;
        let result = async {
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_| WebMultipartError::Invalid)?
            {
                size = size
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| WebMultipartError::AttachmentTooLarge(filename.clone()))?;
                if size > max_attachment_bytes {
                    return Err(WebMultipartError::AttachmentTooLarge(filename.clone()));
                }
                output
                    .write_all(&chunk)
                    .await
                    .map_err(|_| WebMultipartError::Unavailable)?;
            }
            output
                .flush()
                .await
                .map_err(|_| WebMultipartError::Unavailable)?;
            output
                .sync_data()
                .await
                .map_err(|_| WebMultipartError::Unavailable)?;
            Ok(())
        }
        .await;
        drop(output);
        if let Err(error) = result {
            let _ = fs::remove_file(&path).await;
            return Err(error);
        }
        if size == 0 {
            let _ = fs::remove_file(&path).await;
            continue;
        }
        total_attachment_bytes = total_attachment_bytes
            .checked_add(size)
            .ok_or(WebMultipartError::AttachmentsTooLarge)?;
        if total_attachment_bytes > max_total_attachment_bytes {
            let _ = fs::remove_file(&path).await;
            return Err(WebMultipartError::AttachmentsTooLarge);
        }
        uploads.push(OwnedUpload {
            filename,
            content_type,
            path,
            size,
        });
    }

    let request = serde_json::from_slice(data.as_deref().ok_or(WebMultipartError::Invalid)?)
        .map_err(|_| WebMultipartError::Invalid)?;
    Ok(ParsedWebMultipart {
        request: Some(request),
        uploads,
    })
}

fn is_possible_data_field(filename: Option<&str>, content_type: Option<&str>) -> bool {
    if filename.is_none() {
        return true;
    }
    let content_type = base_content_type(content_type);
    matches!(
        content_type,
        "application/json" | "text/json" | "text/plain"
    )
}

fn is_data_field(filename: Option<&str>, content_type: Option<&str>, size: usize) -> bool {
    if filename.is_none() {
        return true;
    }
    let content_type = base_content_type(content_type);
    let filename = filename.unwrap_or_default();
    matches!(
        content_type,
        "application/json" | "text/json" | "text/plain"
    ) && (filename.is_empty()
        || filename.eq_ignore_ascii_case("blob")
        || (content_type == "application/json" && size < MAX_DATA_BYTES))
}

fn base_content_type(value: Option<&str>) -> &str {
    value
        .unwrap_or_default()
        .split_once(';')
        .map_or(value.unwrap_or_default(), |(base, _)| base)
        .trim()
}

async fn read_bounded_field(
    field: &mut multer::Field<'_>,
    limit: usize,
) -> Result<Vec<u8>, WebMultipartError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| WebMultipartError::Invalid)?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(WebMultipartError::Invalid);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn drain_bounded_field(
    field: &mut multer::Field<'_>,
    limit: u64,
) -> Result<(), WebMultipartError> {
    let mut size = 0_u64;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| WebMultipartError::Invalid)?
    {
        size = size
            .checked_add(chunk.len() as u64)
            .ok_or(WebMultipartError::Invalid)?;
        if size > limit {
            return Err(WebMultipartError::Invalid);
        }
    }
    Ok(())
}

async fn secure_upload_directory(path: &Path) -> Result<PathBuf, WebMultipartError> {
    fs::create_dir_all(path)
        .await
        .map_err(|_| WebMultipartError::Unavailable)?;
    let metadata = fs::symlink_metadata(path)
        .await
        .map_err(|_| WebMultipartError::Unavailable)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(WebMultipartError::Unavailable);
    }
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|_| WebMultipartError::Unavailable)?;
    Ok(path.to_owned())
}

async fn create_upload(path: &Path) -> Result<(PathBuf, tokio::fs::File), WebMultipartError> {
    for _ in 0..CREATE_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| WebMultipartError::Unavailable)?;
        let name = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = path.join(format!("upload-{name}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(WebMultipartError::Unavailable),
        }
    }
    Err(WebMultipartError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::fs as std_fs;

    use futures_util::stream;

    use super::*;

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).unwrap();
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("lmyzmail-multipart-{suffix}"));
            std_fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn assert_empty(&self) {
            assert_eq!(std_fs::read_dir(&self.0).unwrap().count(), 0);
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = std_fs::remove_dir_all(&self.0);
        }
    }

    fn data_part(boundary: &str, subject: &str) -> Vec<u8> {
        format!(
            "--{boundary}\r\n\
Content-Disposition: form-data; name=\"data\"\r\n\
Content-Type: application/json\r\n\r\n\
{{\"subject\":\"{subject}\"}}\r\n"
        )
        .into_bytes()
    }

    fn attachment_part(boundary: &str, filename: &str, content: &[u8]) -> Vec<u8> {
        let mut part = format!(
            "--{boundary}\r\n\
Content-Disposition: form-data; name=\"attachments\"; filename=\"{filename}\"\r\n\
Content-Type: text/plain\r\n\r\n"
        )
        .into_bytes();
        part.extend_from_slice(content);
        part.extend_from_slice(b"\r\n");
        part
    }

    fn finish(boundary: &str) -> Vec<u8> {
        format!("--{boundary}--\r\n").into_bytes()
    }

    fn fragmented(body: &[u8], chunk_bytes: usize) -> impl Stream<Item = Result<Bytes, io::Error>> {
        stream::iter(body.chunks(chunk_bytes).map(Bytes::copy_from_slice).map(Ok))
    }

    #[tokio::test]
    async fn fragmented_parse_uses_last_data_and_drop_removes_uploads() {
        let directory = TempDirectory::new();
        let boundary = "lmyzmail-test-boundary";
        let mut body = data_part(boundary, "first");
        body.extend(attachment_part(boundary, "proof.txt", b"hello"));
        body.extend(data_part(boundary, "last"));
        body.extend(finish(boundary));

        let mut parsed = parse(
            fragmented(&body, 3),
            boundary.into(),
            directory.path(),
            body.len() as u64,
            32,
            32,
        )
        .await
        .unwrap();
        assert_eq!(parsed.take_request().subject.as_deref(), Some("last"));
        let attachments = parsed.attachment_inputs();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].filename, "proof.txt");
        assert_eq!(attachments[0].content_type.as_deref(), Some("text/plain"));
        assert_eq!(attachments[0].size, 5);
        assert_eq!(fs::read(&attachments[0].path).await.unwrap(), b"hello");

        drop(parsed);
        directory.assert_empty();
    }

    #[tokio::test]
    async fn per_attachment_limit_rejects_and_cleans_every_upload() {
        let directory = TempDirectory::new();
        let boundary = "lmyzmail-per-file-limit";
        let mut body = attachment_part(boundary, "small.txt", b"ok");
        body.extend(attachment_part(boundary, "large.txt", b"large"));
        body.extend(data_part(boundary, "subject"));
        body.extend(finish(boundary));

        let error = parse(
            fragmented(&body, 2),
            boundary.into(),
            directory.path(),
            body.len() as u64,
            4,
            32,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            WebMultipartError::AttachmentTooLarge(filename) if filename == "large.txt"
        ));
        directory.assert_empty();
    }

    #[tokio::test]
    async fn aggregate_limit_rejects_and_cleans_every_upload() {
        let directory = TempDirectory::new();
        let boundary = "lmyzmail-total-limit";
        let mut body = attachment_part(boundary, "one.txt", b"one");
        body.extend(attachment_part(boundary, "two.txt", b"two"));
        body.extend(data_part(boundary, "subject"));
        body.extend(finish(boundary));

        let error = parse(
            fragmented(&body, 5),
            boundary.into(),
            directory.path(),
            body.len() as u64,
            16,
            5,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, WebMultipartError::AttachmentsTooLarge));
        directory.assert_empty();
    }

    #[tokio::test]
    async fn whole_stream_limit_rejects_without_leaving_uploads() {
        let directory = TempDirectory::new();
        let boundary = "lmyzmail-request-limit";
        let mut body = attachment_part(boundary, "proof.txt", b"hello");
        body.extend(data_part(boundary, "subject"));
        body.extend(finish(boundary));

        let error = parse(
            fragmented(&body, 7),
            boundary.into(),
            directory.path(),
            (body.len() - 1) as u64,
            32,
            32,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, WebMultipartError::Invalid));
        directory.assert_empty();
    }

    #[tokio::test]
    async fn disconnected_stream_cleans_completed_uploads() {
        let directory = TempDirectory::new();
        let boundary = "lmyzmail-disconnect";
        let mut prefix = attachment_part(boundary, "proof.txt", b"hello");
        prefix.extend_from_slice(
            format!(
                "--{boundary}\r\n\
Content-Disposition: form-data; name=\"data\"\r\n\
Content-Type: application/json\r\n\r\n{{"
            )
            .as_bytes(),
        );
        let stream = stream::iter(vec![
            Ok(Bytes::from(prefix)),
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "test reset")),
        ]);

        let error = parse(stream, boundary.into(), directory.path(), 1024, 32, 32)
            .await
            .unwrap_err();
        assert!(matches!(error, WebMultipartError::Invalid));
        directory.assert_empty();
    }
}
