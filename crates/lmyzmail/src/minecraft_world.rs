use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Cursor, Read},
    path::Path,
    sync::{Arc, OnceLock},
};

use flate2::read::{GzDecoder, ZlibDecoder};

const REGION_BYTES: usize = 4096;
const REGION_HEADER_BYTES: usize = REGION_BYTES * 2;
const SECTOR_BYTES: usize = 4096;
const MAX_CHUNK_BYTES: usize = 2 * 1024 * 1024;
const MAX_REGION_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_NBT_DEPTH: usize = 32;
const MAX_NBT_TAGS: usize = 100_000;
const MAX_NBT_ELEMENTS: usize = 65_536;
const MAX_NBT_BYTES: usize = 2 * 1024 * 1024;
const MAX_NBT_AGGREGATE_ELEMENTS: usize = MAX_NBT_BYTES;
// The template is immutable and shared by all sessions, so bound its total
// expanded heap footprint before accepting a configured external world.
const MAX_WORLD_HEAP_BYTES: usize = 512 * 1024 * 1024;

const REGION_SOURCES: &[(i32, i32, &[u8])] = &[
    (
        -1,
        -1,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/worlds/mailroom/region/r.-1.-1.mca"
        )),
    ),
    (
        -1,
        0,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/worlds/mailroom/region/r.-1.0.mca"
        )),
    ),
    (
        0,
        -1,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/worlds/mailroom/region/r.0.-1.mca"
        )),
    ),
    (
        0,
        0,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/worlds/mailroom/region/r.0.0.mca"
        )),
    ),
];

static EMBEDDED_MAILROOM: OnceLock<Result<Arc<WorldTemplate>, String>> = OnceLock::new();

#[derive(Clone, Debug)]
pub enum NbtValue {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    ByteArray(Vec<u8>),
    String(String),
    List {
        element_type: u8,
        values: Vec<NbtValue>,
    },
    Compound(Vec<(String, NbtValue)>),
    IntArray(Vec<i32>),
}

#[derive(Clone, Debug)]
pub struct TileEntity {
    pub x: i32,
    pub y: i32,
    pub z: i32,
    pub id: String,
    pub nbt: NbtValue,
}

#[derive(Clone, Debug)]
pub struct SectionData {
    pub blocks: Vec<u16>,
    pub block_light: Vec<u8>,
    pub sky_light: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ChunkData {
    pub chunk_x: i32,
    pub chunk_z: i32,
    pub sections: Vec<Option<SectionData>>,
    pub biomes: Vec<u8>,
    pub tile_entities: Vec<TileEntity>,
}

#[derive(Clone, Debug)]
pub struct WorldTemplate {
    chunks: Vec<ChunkData>,
}

impl WorldTemplate {
    pub fn load_shared(source: &str) -> io::Result<Arc<Self>> {
        if matches!(source, "worlds/mailroom" | "classpath:worlds/mailroom") {
            return EMBEDDED_MAILROOM
                .get_or_init(|| {
                    Self::embedded_mailroom()
                        .map(Arc::new)
                        .map_err(|error| error.to_string())
                })
                .clone()
                .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message));
        }
        Self::load(source).map(Arc::new)
    }

    pub fn load(source: &str) -> io::Result<Self> {
        if matches!(source, "worlds/mailroom" | "classpath:worlds/mailroom") {
            return Self::embedded_mailroom();
        }
        let base = Path::new(source);
        let mut regions = Vec::new();
        for &(region_x, region_z, _) in REGION_SOURCES {
            let path = base
                .join("region")
                .join(format!("r.{region_x}.{region_z}.mca"));
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Minecraft world region is not a regular file: {}",
                        path.display()
                    ),
                ));
            }
            if metadata.len() > MAX_REGION_FILE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Minecraft world region exceeds byte limit: {}",
                        path.display()
                    ),
                ));
            }
            regions.push(load_region(&read_bounded_file(&path)?, region_x, region_z)?);
        }
        Self::from_regions(regions)
    }

    fn from_regions(regions: Vec<Vec<ChunkData>>) -> io::Result<Self> {
        let mut ordered_regions = Vec::with_capacity(regions.len());
        let mut world_bytes = 0_usize;
        for region in regions {
            // Java loads each .mca into a HashMap and then putAlls it into the
            // world map. Both maps expose their bucket iteration order.
            world_bytes = region.iter().fold(world_bytes, |total, chunk| {
                total.saturating_add(
                    std::mem::size_of::<ChunkData>() + estimated_chunk_heap_bytes(chunk),
                )
            });
            if world_bytes > MAX_WORLD_HEAP_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Minecraft world expanded heap budget exceeded",
                ));
            }
            ordered_regions.push(java_hash_map_order(region, |chunk| {
                pack_chunk_key(chunk.chunk_x, chunk.chunk_z)
            }));
        }
        let chunks = java_hash_map_put_all_order(ordered_regions, |chunk| {
            pack_chunk_key(chunk.chunk_x, chunk.chunk_z)
        });
        if chunks.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Minecraft world contains no valid chunks",
            ));
        }
        Ok(Self { chunks })
    }

    pub fn embedded_mailroom() -> io::Result<Self> {
        let mut regions = Vec::new();
        for &(region_x, region_z, bytes) in REGION_SOURCES {
            regions.push(load_region(bytes, region_x, region_z)?);
        }
        Self::from_regions(regions).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData && error.to_string().contains("no valid")
            {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "embedded Minecraft mailroom contains no valid chunks",
                )
            } else {
                error
            }
        })
    }

    pub fn chunks_near_centers<'a>(
        &'a self,
        centers: &'a [(i32, i32)],
        view_distance: i32,
    ) -> impl Iterator<Item = &'a ChunkData> + 'a {
        let view_distance = i64::from(view_distance);
        self.chunks.iter().filter(move |chunk| {
            centers.iter().any(|&(center_x, center_z)| {
                (i64::from(chunk.chunk_x) - i64::from(center_x)).abs() <= view_distance
                    && (i64::from(chunk.chunk_z) - i64::from(center_z)).abs() <= view_distance
            })
        })
    }

    pub fn chunks(&self) -> &[ChunkData] {
        &self.chunks
    }
}

pub fn serialize_chunk(chunk: &ChunkData, has_sky_light: bool, ground_up: bool) -> (u16, Vec<u8>) {
    let mut mask = 0_u16;
    let mut sections = Vec::new();
    for (index, section) in chunk.sections.iter().enumerate().take(16) {
        if let Some(section) = section {
            mask |= 1 << index;
            sections.push(section);
        }
    }
    let mut data = Vec::with_capacity(
        sections.len() * (8192 + 2048 + usize::from(has_sky_light) * 2048)
            + usize::from(ground_up) * 256,
    );
    for section in &sections {
        for &state in &section.blocks {
            data.extend_from_slice(&state.to_le_bytes());
        }
    }
    for section in &sections {
        data.extend_from_slice(&section.block_light);
    }
    if has_sky_light {
        for section in &sections {
            if let Some(sky_light) = &section.sky_light {
                data.extend_from_slice(sky_light);
            } else {
                data.extend(std::iter::repeat_n(0xff, 2048));
            }
        }
    }
    if ground_up {
        if chunk.biomes.len() == 256 {
            data.extend_from_slice(&chunk.biomes);
        } else {
            data.extend(std::iter::repeat_n(0, 256));
        }
    }
    (mask, data)
}

pub fn write_nbt(value: Option<&NbtValue>, output: &mut Vec<u8>) -> io::Result<()> {
    let Some(value) = value else {
        output.push(0);
        return Ok(());
    };
    if !matches!(value, NbtValue::Compound(_)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft network NBT root must be a compound",
        ));
    }
    output.push(10);
    write_nbt_string("", output)?;
    write_nbt_payload(value, output, 0)
}

fn write_nbt_payload(value: &NbtValue, output: &mut Vec<u8>, depth: usize) -> io::Result<()> {
    if depth > MAX_NBT_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft NBT depth exceeded",
        ));
    }
    match value {
        NbtValue::Byte(value) => output.push(*value as u8),
        NbtValue::Short(value) => output.extend_from_slice(&value.to_be_bytes()),
        NbtValue::Int(value) => output.extend_from_slice(&value.to_be_bytes()),
        NbtValue::Long(value) => output.extend_from_slice(&value.to_be_bytes()),
        NbtValue::Float(value) => output.extend_from_slice(&value.to_bits().to_be_bytes()),
        NbtValue::Double(value) => output.extend_from_slice(&value.to_bits().to_be_bytes()),
        NbtValue::ByteArray(values) => {
            write_nbt_len(values.len(), output)?;
            output.extend_from_slice(values);
        }
        NbtValue::String(value) => write_nbt_string(value, output)?,
        NbtValue::List {
            element_type,
            values,
        } => {
            output.push(*element_type);
            write_nbt_len(values.len(), output)?;
            for value in values {
                write_nbt_payload(value, output, depth + 1)?;
            }
        }
        NbtValue::Compound(values) => {
            for (name, value) in values {
                output.push(nbt_type(value));
                write_nbt_string(name, output)?;
                write_nbt_payload(value, output, depth + 1)?;
            }
            output.push(0);
        }
        NbtValue::IntArray(values) => {
            write_nbt_len(values.len(), output)?;
            for value in values {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
    Ok(())
}

fn nbt_type(value: &NbtValue) -> u8 {
    match value {
        NbtValue::Byte(_) => 1,
        NbtValue::Short(_) => 2,
        NbtValue::Int(_) => 3,
        NbtValue::Long(_) => 4,
        NbtValue::Float(_) => 5,
        NbtValue::Double(_) => 6,
        NbtValue::ByteArray(_) => 7,
        NbtValue::String(_) => 8,
        NbtValue::List { .. } => 9,
        NbtValue::Compound(_) => 10,
        NbtValue::IntArray(_) => 11,
    }
}

fn write_nbt_len(length: usize, output: &mut Vec<u8>) -> io::Result<()> {
    let length = i32::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft NBT collection is too large",
        )
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn write_nbt_string(value: &str, output: &mut Vec<u8>) -> io::Result<()> {
    let bytes = encode_modified_utf8(value);
    let length = u16::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft NBT string is too large",
        )
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&bytes);
    Ok(())
}

fn load_region(bytes: &[u8], region_x: i32, region_z: i32) -> io::Result<Vec<ChunkData>> {
    if bytes.len() < REGION_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft Anvil region header is truncated",
        ));
    }
    let mut chunks = Vec::new();
    for local_z in 0..32_usize {
        for local_x in 0..32_usize {
            let index = (local_z * 32 + local_x) * 4;
            let location = u32::from_be_bytes(bytes[index..index + 4].try_into().unwrap());
            if location == 0 {
                continue;
            }
            let sector_offset = (location >> 8) as usize;
            let sector_count = (location & 0xff) as usize;
            let Some(offset) = sector_offset.checked_mul(SECTOR_BYTES) else {
                continue;
            };
            let Some(sector_bytes) = sector_count.checked_mul(SECTOR_BYTES) else {
                continue;
            };
            if sector_offset < 2
                || sector_count == 0
                || offset > bytes.len()
                || sector_bytes > bytes.len() - offset
                || sector_bytes < 5
            {
                continue;
            }
            let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            if length <= 1 || length + 4 > sector_bytes || length > MAX_CHUNK_BYTES {
                continue;
            }
            let compression = bytes[offset + 4];
            let compressed = &bytes[offset + 5..offset + 4 + length];
            let decompressed = decompress_chunk(compressed, compression)?;
            if let Some(chunk) = parse_chunk(&decompressed)? {
                let expected_x = region_x * 32 + local_x as i32;
                let expected_z = region_z * 32 + local_z as i32;
                if chunk.chunk_x == expected_x && chunk.chunk_z == expected_z {
                    let projected = estimated_world_heap_bytes(&chunks)
                        .saturating_add(estimated_chunk_heap_bytes(&chunk));
                    if projected > MAX_WORLD_HEAP_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Minecraft world expanded heap budget exceeded",
                        ));
                    }
                    chunks.push(chunk);
                }
            }
        }
    }
    Ok(chunks)
}

fn read_bounded_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut limited = file.take(MAX_REGION_FILE_BYTES.saturating_add(1));
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REGION_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Minecraft world region exceeds byte limit: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

fn pack_chunk_key(chunk_x: i32, chunk_z: i32) -> i64 {
    (i64::from(chunk_x) << 32) | i64::from(u32::from_ne_bytes(chunk_z.to_ne_bytes()))
}

fn java_hash(value: i64) -> u32 {
    let raw = (value as u64 ^ ((value as u64) >> 32)) as u32;
    raw ^ (raw >> 16)
}

// OpenJDK HashMap iteration is externally visible in the frozen server's
// chunk order. Equal-hash Long keys treeify, and moveRootToFront changes the
// linked iteration chain, so a bucket-only sort is not equivalent.
const JAVA_INITIAL_CAPACITY: usize = 16;
const JAVA_MAXIMUM_CAPACITY: usize = 1 << 30;
const JAVA_TREEIFY_THRESHOLD: usize = 8;
const JAVA_UNTREEIFY_THRESHOLD: usize = 6;
const JAVA_MIN_TREEIFY_CAPACITY: usize = 64;

#[derive(Clone, Debug)]
struct JavaHashNode {
    hash: u32,
    key: i64,
    insertion: usize,
    next: Option<usize>,
    prev: Option<usize>,
    parent: Option<usize>,
    left: Option<usize>,
    right: Option<usize>,
    red: bool,
    tree: bool,
}

impl JavaHashNode {
    fn new(hash: u32, key: i64, insertion: usize) -> Self {
        Self {
            hash,
            key,
            insertion,
            next: None,
            prev: None,
            parent: None,
            left: None,
            right: None,
            red: false,
            tree: false,
        }
    }
}

#[derive(Default)]
struct JavaHashOrderMap {
    table: Vec<Option<usize>>,
    nodes: Vec<JavaHashNode>,
    threshold: usize,
    size: usize,
}

impl JavaHashOrderMap {
    fn prepare_put_all(&mut self, incoming: usize) {
        if incoming == 0 {
            return;
        }
        if self.table.is_empty() {
            let target = (((incoming as f32) / 0.75_f32) + 1.0_f32) as usize;
            if target > self.threshold {
                self.threshold = java_table_size_for(target);
            }
        } else if incoming > self.threshold {
            self.resize();
        }
    }

    fn insert(&mut self, key: i64, insertion: usize) {
        if self.table.is_empty() {
            self.resize();
        }
        let hash = java_hash(key);
        let bucket = (hash as usize) & (self.table.len() - 1);
        match self.table[bucket] {
            None => {
                let node = self.push_node(hash, key, insertion);
                self.table[bucket] = Some(node);
            }
            Some(head) if self.nodes[head].tree => {
                let node = self.push_node(hash, key, insertion);
                self.nodes[node].tree = true;
                self.put_tree_node(bucket, head, node);
            }
            Some(head) => {
                let mut tail = head;
                let mut bin_count = 0_usize;
                while let Some(next) = self.nodes[tail].next {
                    tail = next;
                    bin_count += 1;
                }
                let node = self.push_node(hash, key, insertion);
                self.nodes[tail].next = Some(node);
                if bin_count >= JAVA_TREEIFY_THRESHOLD - 1 {
                    self.treeify_bucket(bucket);
                }
            }
        }
        self.size += 1;
        if self.size > self.threshold {
            self.resize();
        }
    }

    fn push_node(&mut self, hash: u32, key: i64, insertion: usize) -> usize {
        let index = self.nodes.len();
        self.nodes.push(JavaHashNode::new(hash, key, insertion));
        index
    }

    fn resize(&mut self) {
        let old_table = std::mem::take(&mut self.table);
        let old_capacity = old_table.len();
        let old_threshold = self.threshold;
        let (new_capacity, mut new_threshold) = if old_capacity != 0 {
            if old_capacity >= JAVA_MAXIMUM_CAPACITY {
                self.table = old_table;
                self.threshold = usize::MAX;
                return;
            }
            let capacity = old_capacity * 2;
            let threshold = if old_capacity >= JAVA_INITIAL_CAPACITY {
                old_threshold.saturating_mul(2)
            } else {
                0
            };
            (capacity, threshold)
        } else if old_threshold != 0 {
            (old_threshold, 0)
        } else {
            (JAVA_INITIAL_CAPACITY, 12)
        };
        if new_threshold == 0 {
            new_threshold = ((new_capacity as f32) * 0.75_f32) as usize;
        }
        self.threshold = new_threshold;
        self.table = vec![None; new_capacity];

        for (bucket, head) in old_table.into_iter().enumerate() {
            let Some(head) = head else {
                continue;
            };
            if self.nodes[head].next.is_none() {
                self.nodes[head].prev = None;
                let destination = (self.nodes[head].hash as usize) & (new_capacity - 1);
                self.table[destination] = Some(head);
            } else if self.nodes[head].tree {
                self.split_tree_bin(head, bucket, old_capacity);
            } else {
                self.split_list_bin(head, bucket, old_capacity);
            }
        }
    }

    fn split_list_bin(&mut self, head: usize, bucket: usize, bit: usize) {
        let mut low_head = None;
        let mut low_tail = None;
        let mut high_head = None;
        let mut high_tail = None;
        let mut current = Some(head);
        while let Some(node) = current {
            current = self.nodes[node].next;
            self.nodes[node].next = None;
            self.nodes[node].prev = None;
            if (self.nodes[node].hash as usize) & bit == 0 {
                append_link(&mut self.nodes, &mut low_head, &mut low_tail, node, false);
            } else {
                append_link(&mut self.nodes, &mut high_head, &mut high_tail, node, false);
            }
        }
        self.table[bucket] = low_head;
        self.table[bucket + bit] = high_head;
    }

    fn split_tree_bin(&mut self, head: usize, bucket: usize, bit: usize) {
        let mut low_head = None;
        let mut low_tail = None;
        let mut low_count = 0_usize;
        let mut high_head = None;
        let mut high_tail = None;
        let mut high_count = 0_usize;
        let mut current = Some(head);
        while let Some(node) = current {
            current = self.nodes[node].next;
            self.nodes[node].next = None;
            if (self.nodes[node].hash as usize) & bit == 0 {
                append_link(&mut self.nodes, &mut low_head, &mut low_tail, node, true);
                low_count += 1;
            } else {
                append_link(&mut self.nodes, &mut high_head, &mut high_tail, node, true);
                high_count += 1;
            }
        }

        if let Some(low) = low_head {
            self.table[bucket] = Some(low);
            if low_count <= JAVA_UNTREEIFY_THRESHOLD {
                self.untreeify(low);
            } else if high_head.is_some() {
                self.treeify(low, bucket);
            }
        }
        if let Some(high) = high_head {
            self.table[bucket + bit] = Some(high);
            if high_count <= JAVA_UNTREEIFY_THRESHOLD {
                self.untreeify(high);
            } else if low_head.is_some() {
                self.treeify(high, bucket + bit);
            }
        }
    }

    fn treeify_bucket(&mut self, bucket: usize) {
        if self.table.len() < JAVA_MIN_TREEIFY_CAPACITY {
            self.resize();
            return;
        }
        let Some(head) = self.table[bucket] else {
            return;
        };
        let mut previous = None;
        let mut current = Some(head);
        while let Some(node) = current {
            self.nodes[node].tree = true;
            self.nodes[node].prev = previous;
            self.nodes[node].parent = None;
            self.nodes[node].left = None;
            self.nodes[node].right = None;
            self.nodes[node].red = false;
            previous = Some(node);
            current = self.nodes[node].next;
        }
        self.treeify(head, bucket);
    }

    fn treeify(&mut self, head: usize, bucket: usize) {
        let mut root = None;
        let mut current = Some(head);
        while let Some(node) = current {
            current = self.nodes[node].next;
            self.nodes[node].tree = true;
            self.nodes[node].parent = None;
            self.nodes[node].left = None;
            self.nodes[node].right = None;
            if let Some(mut parent) = root {
                loop {
                    let direction = self.compare_nodes(node, parent);
                    let child = if direction <= 0 {
                        self.nodes[parent].left
                    } else {
                        self.nodes[parent].right
                    };
                    if let Some(child) = child {
                        parent = child;
                        continue;
                    }
                    self.nodes[node].parent = Some(parent);
                    if direction <= 0 {
                        self.nodes[parent].left = Some(node);
                    } else {
                        self.nodes[parent].right = Some(node);
                    }
                    root = Some(self.balance_insertion(root.unwrap(), node));
                    break;
                }
            } else {
                self.nodes[node].red = false;
                root = Some(node);
            }
        }
        if let Some(root) = root {
            self.move_root_to_front(bucket, root);
        }
    }

    fn put_tree_node(&mut self, bucket: usize, head: usize, node: usize) {
        let mut root = self.root_of(head);
        let mut parent = root;
        loop {
            let direction = self.compare_nodes(node, parent);
            let child = if direction <= 0 {
                self.nodes[parent].left
            } else {
                self.nodes[parent].right
            };
            if let Some(child) = child {
                parent = child;
                continue;
            }
            let next = self.nodes[parent].next;
            self.nodes[node].parent = Some(parent);
            self.nodes[node].prev = Some(parent);
            self.nodes[node].next = next;
            self.nodes[parent].next = Some(node);
            if let Some(next) = next {
                self.nodes[next].prev = Some(node);
            }
            if direction <= 0 {
                self.nodes[parent].left = Some(node);
            } else {
                self.nodes[parent].right = Some(node);
            }
            root = self.balance_insertion(root, node);
            self.move_root_to_front(bucket, root);
            return;
        }
    }

    fn compare_nodes(&self, left: usize, right: usize) -> i32 {
        // HashMap stores the spread hash in a signed Java int. Bucket masks
        // use its bits, while tree-bin comparisons use signed ordering.
        match (self.nodes[left].hash as i32).cmp(&(self.nodes[right].hash as i32)) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => match self.nodes[left].key.cmp(&self.nodes[right].key) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            },
        }
    }

    fn root_of(&self, mut node: usize) -> usize {
        while let Some(parent) = self.nodes[node].parent {
            node = parent;
        }
        node
    }

    fn move_root_to_front(&mut self, bucket: usize, root: usize) {
        let first = self.table[bucket];
        if first == Some(root) {
            return;
        }
        let next = self.nodes[root].next;
        let previous = self.nodes[root].prev;
        if let Some(next) = next {
            self.nodes[next].prev = previous;
        }
        if let Some(previous) = previous {
            self.nodes[previous].next = next;
        }
        if let Some(first) = first {
            self.nodes[first].prev = Some(root);
        }
        self.nodes[root].next = first;
        self.nodes[root].prev = None;
        self.table[bucket] = Some(root);
    }

    fn balance_insertion(&mut self, mut root: usize, mut node: usize) -> usize {
        self.nodes[node].red = true;
        loop {
            let Some(parent) = self.nodes[node].parent else {
                self.nodes[node].red = false;
                return node;
            };
            if !self.nodes[parent].red {
                return root;
            }
            let Some(grandparent) = self.nodes[parent].parent else {
                return root;
            };
            if self.nodes[grandparent].left == Some(parent) {
                let uncle = self.nodes[grandparent].right;
                if uncle.is_some_and(|uncle| self.nodes[uncle].red) {
                    self.nodes[parent].red = false;
                    self.nodes[uncle.unwrap()].red = false;
                    self.nodes[grandparent].red = true;
                    node = grandparent;
                    continue;
                }
                let mut parent = parent;
                let mut grandparent = grandparent;
                if self.nodes[parent].right == Some(node) {
                    node = parent;
                    root = self.rotate_left(root, node);
                    let Some(updated_parent) = self.nodes[node].parent else {
                        continue;
                    };
                    parent = updated_parent;
                    let Some(updated_grandparent) = self.nodes[parent].parent else {
                        continue;
                    };
                    grandparent = updated_grandparent;
                }
                self.nodes[parent].red = false;
                self.nodes[grandparent].red = true;
                root = self.rotate_right(root, grandparent);
            } else {
                let uncle = self.nodes[grandparent].left;
                if uncle.is_some_and(|uncle| self.nodes[uncle].red) {
                    self.nodes[parent].red = false;
                    self.nodes[uncle.unwrap()].red = false;
                    self.nodes[grandparent].red = true;
                    node = grandparent;
                    continue;
                }
                let mut parent = parent;
                let mut grandparent = grandparent;
                if self.nodes[parent].left == Some(node) {
                    node = parent;
                    root = self.rotate_right(root, node);
                    let Some(updated_parent) = self.nodes[node].parent else {
                        continue;
                    };
                    parent = updated_parent;
                    let Some(updated_grandparent) = self.nodes[parent].parent else {
                        continue;
                    };
                    grandparent = updated_grandparent;
                }
                self.nodes[parent].red = false;
                self.nodes[grandparent].red = true;
                root = self.rotate_left(root, grandparent);
            }
        }
    }

    fn rotate_left(&mut self, mut root: usize, pivot: usize) -> usize {
        let Some(right) = self.nodes[pivot].right else {
            return root;
        };
        let right_left = self.nodes[right].left;
        self.nodes[pivot].right = right_left;
        if let Some(right_left) = right_left {
            self.nodes[right_left].parent = Some(pivot);
        }
        let parent = self.nodes[pivot].parent;
        self.nodes[right].parent = parent;
        if let Some(parent) = parent {
            if self.nodes[parent].left == Some(pivot) {
                self.nodes[parent].left = Some(right);
            } else {
                self.nodes[parent].right = Some(right);
            }
        } else {
            root = right;
            self.nodes[right].red = false;
        }
        self.nodes[right].left = Some(pivot);
        self.nodes[pivot].parent = Some(right);
        root
    }

    fn rotate_right(&mut self, mut root: usize, pivot: usize) -> usize {
        let Some(left) = self.nodes[pivot].left else {
            return root;
        };
        let left_right = self.nodes[left].right;
        self.nodes[pivot].left = left_right;
        if let Some(left_right) = left_right {
            self.nodes[left_right].parent = Some(pivot);
        }
        let parent = self.nodes[pivot].parent;
        self.nodes[left].parent = parent;
        if let Some(parent) = parent {
            if self.nodes[parent].right == Some(pivot) {
                self.nodes[parent].right = Some(left);
            } else {
                self.nodes[parent].left = Some(left);
            }
        } else {
            root = left;
            self.nodes[left].red = false;
        }
        self.nodes[left].right = Some(pivot);
        self.nodes[pivot].parent = Some(left);
        root
    }

    fn untreeify(&mut self, head: usize) {
        let mut current = Some(head);
        while let Some(node) = current {
            self.nodes[node].tree = false;
            self.nodes[node].prev = None;
            self.nodes[node].parent = None;
            self.nodes[node].left = None;
            self.nodes[node].right = None;
            self.nodes[node].red = false;
            current = self.nodes[node].next;
        }
    }

    fn insertion_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.size);
        let mut seen = vec![false; self.nodes.len()];
        for head in &self.table {
            let mut current = *head;
            while let Some(node) = current {
                assert!(
                    !seen[node],
                    "Java HashMap compatibility chain contains a cycle"
                );
                seen[node] = true;
                order.push(self.nodes[node].insertion);
                current = self.nodes[node].next;
            }
        }
        assert_eq!(order.len(), self.size);
        order
    }
}

fn append_link(
    nodes: &mut [JavaHashNode],
    head: &mut Option<usize>,
    tail: &mut Option<usize>,
    node: usize,
    with_previous: bool,
) {
    nodes[node].prev = with_previous.then_some(*tail).flatten();
    if let Some(previous) = *tail {
        nodes[previous].next = Some(node);
    } else {
        *head = Some(node);
    }
    *tail = Some(node);
}

fn java_table_size_for(capacity: usize) -> usize {
    capacity
        .max(1)
        .next_power_of_two()
        .min(JAVA_MAXIMUM_CAPACITY)
}

fn java_hash_map_order<T>(entries: Vec<T>, key: impl Fn(&T) -> i64) -> Vec<T> {
    let mut map = JavaHashOrderMap::default();
    for (insertion, entry) in entries.iter().enumerate() {
        map.insert(key(entry), insertion);
    }
    reorder_entries(entries, map.insertion_order())
}

fn java_hash_map_put_all_order<T>(groups: Vec<Vec<T>>, key: impl Fn(&T) -> i64) -> Vec<T> {
    let mut map = JavaHashOrderMap::default();
    let mut entries = Vec::new();
    for group in groups {
        map.prepare_put_all(group.len());
        for entry in group {
            let insertion = entries.len();
            map.insert(key(&entry), insertion);
            entries.push(entry);
        }
    }
    reorder_entries(entries, map.insertion_order())
}

fn reorder_entries<T>(entries: Vec<T>, order: Vec<usize>) -> Vec<T> {
    let mut entries = entries.into_iter().map(Some).collect::<Vec<_>>();
    order
        .into_iter()
        .map(|index| entries[index].take().expect("Java HashMap order is unique"))
        .collect()
}

fn estimated_world_heap_bytes(chunks: &[ChunkData]) -> usize {
    let base = chunks
        .len()
        .saturating_mul(std::mem::size_of::<ChunkData>());
    chunks.iter().fold(base, |total, chunk| {
        total.saturating_add(estimated_chunk_heap_bytes(chunk))
    })
}

fn estimated_chunk_heap_bytes(chunk: &ChunkData) -> usize {
    let mut total = chunk.sections.capacity() * std::mem::size_of::<Option<SectionData>>();
    total = total.saturating_add(chunk.biomes.capacity());
    total =
        total.saturating_add(chunk.tile_entities.capacity() * std::mem::size_of::<TileEntity>());
    for section in chunk.sections.iter().flatten() {
        total = total
            .saturating_add(section.blocks.capacity() * std::mem::size_of::<u16>())
            .saturating_add(section.block_light.capacity())
            .saturating_add(section.sky_light.as_ref().map_or(0, Vec::capacity));
    }
    for tile_entity in &chunk.tile_entities {
        total = total
            .saturating_add(tile_entity.id.capacity())
            .saturating_add(estimated_nbt_heap_bytes(&tile_entity.nbt));
    }
    total
}

fn estimated_nbt_heap_bytes(value: &NbtValue) -> usize {
    let base = std::mem::size_of::<NbtValue>();
    match value {
        NbtValue::ByteArray(values) => base.saturating_add(values.capacity()),
        NbtValue::String(value) => base.saturating_add(value.capacity()),
        NbtValue::List { values, .. } => values.iter().fold(
            base.saturating_add(values.capacity() * std::mem::size_of::<NbtValue>()),
            |total, value| total.saturating_add(estimated_nbt_heap_bytes(value)),
        ),
        NbtValue::Compound(entries) => entries.iter().fold(
            base.saturating_add(entries.capacity() * std::mem::size_of::<(String, NbtValue)>()),
            |total, (name, value)| {
                total
                    .saturating_add(name.capacity())
                    .saturating_add(estimated_nbt_heap_bytes(value))
            },
        ),
        NbtValue::IntArray(values) => {
            base.saturating_add(values.capacity() * std::mem::size_of::<i32>())
        }
        _ => base,
    }
}

fn decompress_chunk(compressed: &[u8], compression: u8) -> io::Result<Vec<u8>> {
    let reader = Cursor::new(compressed);
    let mut decoder: Box<dyn Read> = match compression {
        1 => Box::new(GzDecoder::new(reader)),
        2 => Box::new(ZlibDecoder::new(reader)),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown Anvil compression",
            ));
        }
    };
    let mut output = Vec::new();
    let mut limited = (&mut decoder).take((MAX_CHUNK_BYTES + 1) as u64);
    limited.read_to_end(&mut output)?;
    if output.len() > MAX_CHUNK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Anvil chunk exceeds byte budget",
        ));
    }
    Ok(output)
}

fn parse_chunk(bytes: &[u8]) -> io::Result<Option<ChunkData>> {
    let mut reader = NbtReader::new(bytes);
    let root = reader.read_root()?;
    let Some(level) = compound_field(&root, "Level") else {
        return Ok(None);
    };
    let (Some(chunk_x), Some(chunk_z)) = (int_field(level, "xPos"), int_field(level, "zPos"))
    else {
        return Ok(None);
    };
    let biomes = byte_array_field(level, "Biomes")
        .filter(|bytes| bytes.len() == 256)
        .map_or_else(|| vec![0; 256], ToOwned::to_owned);

    let mut sections = vec![None; 16];
    if let Some(NbtValue::List { values, .. }) = compound_field(level, "Sections") {
        for section in values {
            let Some(y) = byte_field(section, "Y").map(|value| value as u8) else {
                continue;
            };
            if y >= 16 {
                continue;
            }
            let Some(blocks) =
                byte_array_field(section, "Blocks").filter(|value| value.len() == 4096)
            else {
                continue;
            };
            let Some(metadata) =
                byte_array_field(section, "Data").filter(|value| value.len() == 2048)
            else {
                continue;
            };
            let block_light = byte_array_field(section, "BlockLight")
                .filter(|value| value.len() == 2048)
                .map_or_else(|| vec![0; 2048], ToOwned::to_owned);
            let sky_light = byte_array_field(section, "SkyLight")
                .filter(|value| value.len() == 2048)
                .map(ToOwned::to_owned);
            let add = byte_array_field(section, "Add").filter(|value| value.len() == 2048);
            let mut states = vec![0_u16; 4096];
            for index in 0..4096 {
                let mut block_id = u16::from(blocks[index]);
                if let Some(add) = add {
                    block_id |= u16::from(nibble(add, index)) << 8;
                }
                states[index] = (block_id << 4) | u16::from(nibble(metadata, index));
            }
            sections[usize::from(y)] = Some(SectionData {
                blocks: states,
                block_light,
                sky_light,
            });
        }
    }

    let mut tile_entries: Vec<(i64, Option<TileEntity>)> = Vec::new();
    let mut tile_indices: HashMap<i64, usize> = HashMap::new();
    if let Some(NbtValue::List { values, .. }) = compound_field(level, "TileEntities") {
        for value in values {
            if !matches!(value, NbtValue::Compound(_)) {
                continue;
            }
            let x = int_field(value, "x").unwrap_or_default();
            let y = int_field(value, "y").unwrap_or_default();
            let z = int_field(value, "z").unwrap_or_default();
            let key = pack_block_position(x, y, z);
            let tile_entity = match string_field(value, "id") {
                Some(id @ ("Sign" | "Banner")) => Some(TileEntity {
                    x,
                    y,
                    z,
                    id: id.to_owned(),
                    nbt: value.clone(),
                }),
                _ => None,
            };
            if let Some(&index) = tile_indices.get(&key) {
                tile_entries[index].1 = tile_entity;
            } else {
                tile_indices.insert(key, tile_entries.len());
                tile_entries.push((key, tile_entity));
            }
        }
    }
    let tile_entities = java_hash_map_order(tile_entries, |(key, _)| *key)
        .into_iter()
        .filter_map(|(_, tile_entity)| tile_entity)
        .collect();

    Ok(Some(ChunkData {
        chunk_x,
        chunk_z,
        sections,
        biomes,
        tile_entities,
    }))
}

fn nibble(bytes: &[u8], index: usize) -> u8 {
    if index & 1 == 0 {
        bytes[index >> 1] & 0x0f
    } else {
        bytes[index >> 1] >> 4
    }
}

fn pack_block_position(x: i32, y: i32, z: i32) -> i64 {
    ((i64::from(x) & 0x3ff_ffff) << 38)
        | ((i64::from(y) & 0xfff) << 26)
        | (i64::from(z) & 0x3ff_ffff)
}

fn compound_field<'a>(value: &'a NbtValue, name: &str) -> Option<&'a NbtValue> {
    let NbtValue::Compound(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn int_field(value: &NbtValue, name: &str) -> Option<i32> {
    match compound_field(value, name)? {
        NbtValue::Byte(value) => Some(i32::from(*value)),
        NbtValue::Short(value) => Some(i32::from(*value)),
        NbtValue::Int(value) => Some(*value),
        NbtValue::Long(value) => i32::try_from(*value).ok(),
        _ => None,
    }
}

fn byte_field(value: &NbtValue, name: &str) -> Option<i8> {
    match compound_field(value, name)? {
        NbtValue::Byte(value) => Some(*value),
        _ => None,
    }
}

fn byte_array_field<'a>(value: &'a NbtValue, name: &str) -> Option<&'a [u8]> {
    match compound_field(value, name)? {
        NbtValue::ByteArray(value) => Some(value),
        _ => None,
    }
}

fn string_field<'a>(value: &'a NbtValue, name: &str) -> Option<&'a str> {
    match compound_field(value, name)? {
        NbtValue::String(value) => Some(value),
        _ => None,
    }
}

struct NbtReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
    tags: usize,
    elements: usize,
}

impl<'a> NbtReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            cursor: 0,
            tags: 0,
            elements: 0,
        }
    }

    fn read_root(&mut self) -> io::Result<NbtValue> {
        if self.read_u8()? != 10 {
            return Err(invalid_nbt("root is not a compound"));
        }
        let _ = self.read_string()?;
        self.record_tag()?;
        self.read_compound(0)
    }

    fn read_compound(&mut self, depth: usize) -> io::Result<NbtValue> {
        self.check_depth(depth)?;
        let mut entries = Vec::new();
        loop {
            let kind = self.read_u8()?;
            if kind == 0 {
                break;
            }
            if !(1..=11).contains(&kind) {
                return Err(invalid_nbt("tag type is unknown"));
            }
            let name = self.read_string()?;
            self.record_tag()?;
            let value = self.read_payload(kind, depth + 1)?;
            entries.push((name, value));
        }
        Ok(NbtValue::Compound(entries))
    }

    fn read_payload(&mut self, kind: u8, depth: usize) -> io::Result<NbtValue> {
        self.check_depth(depth)?;
        match kind {
            1 => Ok(NbtValue::Byte(self.read_i8()?)),
            2 => Ok(NbtValue::Short(self.read_i16()?)),
            3 => Ok(NbtValue::Int(self.read_i32()?)),
            4 => Ok(NbtValue::Long(self.read_i64()?)),
            5 => Ok(NbtValue::Float(f32::from_bits(self.read_u32()?))),
            6 => Ok(NbtValue::Double(f64::from_bits(self.read_u64()?))),
            7 => Ok(NbtValue::ByteArray(self.read_byte_array()?)),
            8 => Ok(NbtValue::String(self.read_string()?)),
            9 => {
                let element_type = self.read_u8()?;
                let count = self.read_count()?;
                if element_type == 0 && count != 0 {
                    return Err(invalid_nbt("TAG_End list is not empty"));
                }
                if element_type > 11 {
                    return Err(invalid_nbt("list element type is unknown"));
                }
                let mut values = Vec::new();
                values
                    .try_reserve_exact(count)
                    .map_err(|_| invalid_nbt("list allocation failed"))?;
                for _ in 0..count {
                    self.record_tag()?;
                    values.push(self.read_payload(element_type, depth + 1)?);
                }
                Ok(NbtValue::List {
                    element_type,
                    values,
                })
            }
            10 => self.read_compound(depth),
            11 => {
                let count = self.read_count()?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(count)
                    .map_err(|_| invalid_nbt("int array allocation failed"))?;
                for _ in 0..count {
                    values.push(self.read_i32()?);
                }
                Ok(NbtValue::IntArray(values))
            }
            _ => Err(invalid_nbt("tag type is unknown")),
        }
    }

    fn check_depth(&self, depth: usize) -> io::Result<()> {
        if depth > MAX_NBT_DEPTH {
            Err(invalid_nbt("nesting depth exceeded"))
        } else {
            Ok(())
        }
    }

    fn record_tag(&mut self) -> io::Result<()> {
        self.tags = self
            .tags
            .checked_add(1)
            .ok_or_else(|| invalid_nbt("tag count overflowed"))?;
        if self.tags > MAX_NBT_TAGS {
            Err(invalid_nbt("tag count exceeded"))
        } else {
            Ok(())
        }
    }

    fn read_count(&mut self) -> io::Result<usize> {
        let count = self.read_i32()?;
        if count < 0 || count as usize > MAX_NBT_ELEMENTS {
            return Err(invalid_nbt("collection length exceeded"));
        }
        self.elements = self
            .elements
            .checked_add(count as usize)
            .ok_or_else(|| invalid_nbt("element count overflowed"))?;
        if self.elements > MAX_NBT_AGGREGATE_ELEMENTS {
            return Err(invalid_nbt("aggregate element count exceeded"));
        }
        Ok(count as usize)
    }

    fn read_byte_array(&mut self) -> io::Result<Vec<u8>> {
        let count = self.read_count()?;
        self.take(count).map(ToOwned::to_owned)
    }

    fn read_string(&mut self) -> io::Result<String> {
        let count = usize::from(self.read_u16()?);
        decode_modified_utf8(self.take(count)?)
    }

    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or_else(|| invalid_nbt("cursor overflowed"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| invalid_nbt("input is truncated"))?;
        self.cursor = end;
        if self.cursor > MAX_NBT_BYTES {
            return Err(invalid_nbt("input byte budget exceeded"));
        }
        Ok(value)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_i8(&mut self) -> io::Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn read_i16(&mut self) -> io::Result<i16> {
        Ok(i16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn read_i32(&mut self) -> io::Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn read_i64(&mut self) -> io::Result<i64> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
}

fn invalid_nbt(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Minecraft NBT {message}"),
    )
}

fn decode_modified_utf8(bytes: &[u8]) -> io::Result<String> {
    let mut units = Vec::new();
    units
        .try_reserve_exact(bytes.len())
        .map_err(|_| invalid_nbt("string allocation failed"))?;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let first = bytes[cursor];
        match first {
            0x01..=0x7f => {
                units.push(u16::from(first));
                cursor += 1;
            }
            0xc0..=0xdf => {
                let second = *bytes
                    .get(cursor + 1)
                    .ok_or_else(|| invalid_nbt("modified UTF-8 is truncated"))?;
                if second & 0xc0 != 0x80 {
                    return Err(invalid_nbt("modified UTF-8 continuation is invalid"));
                }
                let unit = (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f);
                if unit != 0 && unit < 0x80 {
                    return Err(invalid_nbt("modified UTF-8 is overlong"));
                }
                units.push(unit);
                cursor += 2;
            }
            0xe0..=0xef => {
                let second = *bytes
                    .get(cursor + 1)
                    .ok_or_else(|| invalid_nbt("modified UTF-8 is truncated"))?;
                let third = *bytes
                    .get(cursor + 2)
                    .ok_or_else(|| invalid_nbt("modified UTF-8 is truncated"))?;
                if second & 0xc0 != 0x80 || third & 0xc0 != 0x80 {
                    return Err(invalid_nbt("modified UTF-8 continuation is invalid"));
                }
                let unit = (u16::from(first & 0x0f) << 12)
                    | (u16::from(second & 0x3f) << 6)
                    | u16::from(third & 0x3f);
                if unit < 0x800 {
                    return Err(invalid_nbt("modified UTF-8 is overlong"));
                }
                units.push(unit);
                cursor += 3;
            }
            _ => return Err(invalid_nbt("modified UTF-8 lead byte is invalid")),
        }
    }
    String::from_utf16(&units).map_err(|_| invalid_nbt("modified UTF-8 has invalid surrogates"))
}

fn encode_modified_utf8(value: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len());
    for unit in value.encode_utf16() {
        match unit {
            0 => output.extend_from_slice(&[0xc0, 0x80]),
            1..=0x7f => output.push(unit as u8),
            0x80..=0x7ff => {
                output.push((0xc0 | (unit >> 6)) as u8);
                output.push((0x80 | (unit & 0x3f)) as u8);
            }
            _ => {
                output.push((0xe0 | (unit >> 12)) as u8);
                output.push((0x80 | ((unit >> 6) & 0x3f)) as u8);
                output.push((0x80 | (unit & 0x3f)) as u8);
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, io::Write};

    use flate2::{Compression, write::ZlibEncoder};
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn embedded_mailroom_is_bounded_and_serializable() {
        let world = WorldTemplate::embedded_mailroom().expect("embedded mailroom must load");
        let coordinates = world
            .chunks()
            .iter()
            .map(|chunk| (chunk.chunk_x, chunk.chunk_z))
            .collect::<HashSet<_>>();
        assert_eq!(world.chunks().len(), 3_209);
        assert_eq!(coordinates.len(), world.chunks().len());
        assert!(estimated_world_heap_bytes(world.chunks()) <= MAX_WORLD_HEAP_BYTES);

        let tile_counts = world
            .chunks()
            .iter()
            .flat_map(|chunk| &chunk.tile_entities)
            .fold((0_usize, 0_usize), |(signs, banners), tile| {
                match tile.id.as_str() {
                    "Sign" => (signs + 1, banners),
                    "Banner" => (signs, banners + 1),
                    other => panic!("unexpected retained tile entity {other}"),
                }
            });
        assert_eq!(tile_counts, (5, 0));

        let expected = [
            (
                -26,
                -26,
                0x001f,
                61_696,
                "1072e9ddbec505e6b9b3a72e6d30f0875ace4c575dbdccb512f714381727105c",
            ),
            (
                -18,
                -18,
                0x001f,
                61_696,
                "7d2199b43a4bc49e4ff23257f7bda403884e54a73be602d13c672f43655046fa",
            ),
            (
                -22,
                -22,
                0x03ff,
                123_136,
                "61d6151a84b206b945c91b26aaf6a4d10cd03275557605fb02a1f64234ecb98f",
            ),
            (
                -24,
                -24,
                0x001f,
                61_696,
                "8177a25f583c5f35666468908ae0ad955bfbc152e76d56617cdf02cc4a8426d1",
            ),
            (
                -20,
                -20,
                0x001f,
                61_696,
                "6e55eeb1cbe5f5ba9e5df6e9cbebf947956dc44c16fc879348460799527ea0b1",
            ),
        ];
        for (chunk, (x, z, expected_mask, expected_len, expected_digest)) in
            world.chunks().iter().zip(expected)
        {
            let (mask, bytes) = serialize_chunk(chunk, true, true);
            assert_eq!((chunk.chunk_x, chunk.chunk_z), (x, z));
            assert_eq!(mask, expected_mask);
            assert_eq!(bytes.len(), expected_len);
            assert_eq!(sha256_hex(&bytes), expected_digest);
        }
    }

    #[test]
    fn embedded_mailroom_bytes_are_pinned_to_the_frozen_java_commit() {
        let manifest: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/worlds/mailroom/SOURCE.json"
        )))
        .unwrap();
        assert_eq!(manifest["schema_version"], 1);
        assert_eq!(
            manifest["source_commit"],
            "5dac2ab2922c30c726c4a83d7626c95ad4e231c8"
        );
        assert_eq!(manifest["byte_source"], "frozen_java_oracle_commit");

        for ((region_x, region_z, bytes), expected_path) in REGION_SOURCES.iter().zip([
            "region/r.-1.-1.mca",
            "region/r.-1.0.mca",
            "region/r.0.-1.mca",
            "region/r.0.0.mca",
        ]) {
            let declared = manifest["files"][expected_path].as_str().unwrap();
            assert_eq!(sha256_hex(bytes), declared, "region {region_x},{region_z}");
        }
    }

    #[test]
    fn modified_utf8_round_trips_nul_and_supplementary_code_points() {
        let value = "A\0\u{80}\u{800}\u{1f4e7}";
        let encoded = encode_modified_utf8(value);
        assert!(!encoded.contains(&0));
        assert_eq!(decode_modified_utf8(&encoded).unwrap(), value);
        assert!(decode_modified_utf8(&[0]).is_err());
        assert!(decode_modified_utf8(&[0xc1, 0x81]).is_err());
        assert!(decode_modified_utf8(&[0xed, 0xa0, 0x80]).is_err());
    }

    #[test]
    fn nbt_writer_rejects_non_compound_and_excessive_depth() {
        assert!(write_nbt(Some(&NbtValue::Int(1)), &mut Vec::new()).is_err());

        let mut nested = NbtValue::Compound(Vec::new());
        for _ in 0..=MAX_NBT_DEPTH + 1 {
            nested = NbtValue::Compound(vec![("nested".to_owned(), nested)]);
        }
        assert!(write_nbt(Some(&nested), &mut Vec::new()).is_err());
    }

    #[test]
    fn nbt_reader_rejects_truncation_and_oversized_collection() {
        assert!(NbtReader::new(&[10, 0]).read_root().is_err());

        let mut bytes = vec![10, 0, 0, 7, 0, 0];
        bytes.extend_from_slice(&((MAX_NBT_ELEMENTS as i32) + 1).to_be_bytes());
        assert!(NbtReader::new(&bytes).read_root().is_err());
    }

    #[test]
    fn chunk_decompression_rejects_unknown_codec_and_expansion_bomb() {
        assert!(decompress_chunk(b"payload", 3).is_err());

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&vec![0_u8; MAX_CHUNK_BYTES + 1]).unwrap();
        let compressed = encoder.finish().unwrap();
        let error = decompress_chunk(&compressed, 2).unwrap_err();
        assert!(error.to_string().contains("byte budget"));
    }

    #[test]
    fn java_hash_map_order_uses_bucket_then_insertion_order() {
        let ordered = java_hash_map_order(vec![16_i64, 0, 1], |value| *value);
        assert_eq!(ordered, vec![16, 0, 1]);

        let resized = java_hash_map_order((0_i64..13).collect(), |value| *value);
        assert_eq!(resized, (0_i64..13).collect::<Vec<_>>());
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}
