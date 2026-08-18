use std::{sync::OnceLock, time::Instant};

use tokio_util::sync::CancellationToken;

#[cfg(test)]
use crate::mail_render::resolve_render_backend;
use crate::{
    dispatch_observer::{self, DispatchComponent},
    mail_render::RenderBackend,
};

const MAX_BLOCK_PIXELS: usize = 4096;
const MAX_MAP_VIDEO_PIXELS: usize = 16 * 16 * 128 * 128;

#[derive(Clone, Copy)]
struct BlockPaletteEntry {
    state_id: u16,
    lab: [f32; 3],
}

// Frozen from the 1.8.0 C palette. The order and precomputed CIELAB values are
// part of the block-video output contract; state IDs are the Java 1.8.9 registry
// mapping, so no JVM or native palette lookup is needed at runtime.
const BLOCK_PALETTE: [BlockPaletteEntry; 152] = [
    BlockPaletteEntry {
        state_id: 2768,
        lab: [5.88, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 784,
        lab: [6.1, 3.99, -7.84],
    },
    BlockPaletteEntry {
        state_id: 575,
        lab: [7.69, 1.98, 0.7],
    },
    BlockPaletteEntry {
        state_id: 2559,
        lab: [9.35, 5.95, 7.1],
    },
    BlockPaletteEntry {
        state_id: 1792,
        lab: [10.92, 11.74, 1.98],
    },
    BlockPaletteEntry {
        state_id: 694,
        lab: [10.92, 11.74, 1.98],
    },
    BlockPaletteEntry {
        state_id: 273,
        lab: [12.52, 6.07, 13.74],
    },
    BlockPaletteEntry {
        state_id: 2593,
        lab: [17.36, 2.17, 13.7],
    },
    BlockPaletteEntry {
        state_id: 2005,
        lab: [18.16, 7.05, 18.18],
    },
    BlockPaletteEntry {
        state_id: 85,
        lab: [18.16, 7.05, 18.18],
    },
    BlockPaletteEntry {
        state_id: 2551,
        lab: [18.73, 6.4, 6.8],
    },
    BlockPaletteEntry {
        state_id: 1968,
        lab: [20.48, 10.5, 15.51],
    },
    BlockPaletteEntry {
        state_id: 2556,
        lab: [23.91, 9.69, 14.22],
    },
    BlockPaletteEntry {
        state_id: 572,
        lab: [24.09, 10.13, 17.73],
    },
    BlockPaletteEntry {
        state_id: 2432,
        lab: [36.95, 54.92, 46.97],
    },
    BlockPaletteEntry {
        state_id: 571,
        lab: [28.01, 24.5, -48.6],
    },
    BlockPaletteEntry {
        state_id: 567,
        lab: [27.09, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 573,
        lab: [27.69, -15.57, 23.8],
    },
    BlockPaletteEntry {
        state_id: 2555,
        lab: [27.96, 13.16, -16.25],
    },
    BlockPaletteEntry {
        state_id: 1392,
        lab: [30.1, 25.06, 12.28],
    },
    BlockPaletteEntry {
        state_id: 352,
        lab: [30.11, 15.05, -42.74],
    },
    BlockPaletteEntry {
        state_id: 1408,
        lab: [29.02, 7.21, 10.86],
    },
    BlockPaletteEntry {
        state_id: 275,
        lab: [30.01, 2.91, 27.32],
    },
    BlockPaletteEntry {
        state_id: 574,
        lab: [36.48, 41.25, 24.4],
    },
    BlockPaletteEntry {
        state_id: 1344,
        lab: [32.12, 11.98, 16.01],
    },
    BlockPaletteEntry {
        state_id: 400,
        lab: [32.12, 11.98, 16.01],
    },
    BlockPaletteEntry {
        state_id: 2558,
        lab: [36.71, 33.73, 25.59],
    },
    BlockPaletteEntry {
        state_id: 1296,
        lab: [37.24, -40.78, 34.82],
    },
    BlockPaletteEntry {
        state_id: 2557,
        lab: [33.75, -10.07, 22.98],
    },
    BlockPaletteEntry {
        state_id: 2690,
        lab: [34.9, -13.64, 4.21],
    },
    BlockPaletteEntry {
        state_id: 2001,
        lab: [35.2, 6.77, 22.47],
    },
    BlockPaletteEntry {
        state_id: 81,
        lab: [35.2, 6.77, 22.47],
    },
    BlockPaletteEntry {
        state_id: 2554,
        lab: [35.8, 22.88, -0.7],
    },
    BlockPaletteEntry {
        state_id: 272,
        lab: [35.87, 4.31, 21.49],
    },
    BlockPaletteEntry {
        state_id: 112,
        lab: [35.72, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 570,
        lab: [40.14, 49.95, -52.67],
    },
    BlockPaletteEntry {
        state_id: 752,
        lab: [38.68, 3.75, 20.46],
    },
    BlockPaletteEntry {
        state_id: 2553,
        lab: [38.31, -1.58, -0.55],
    },
    BlockPaletteEntry {
        state_id: 49,
        lab: [39.4, 10.11, 21.05],
    },
    BlockPaletteEntry {
        state_id: 1760,
        lab: [39.67, 8.53, 12.23],
    },
    BlockPaletteEntry {
        state_id: 1984,
        lab: [40.15, 7.89, 24.36],
    },
    BlockPaletteEntry {
        state_id: 2448,
        lab: [40.31, 15.93, 9.63],
    },
    BlockPaletteEntry {
        state_id: 50,
        lab: [40.39, 10.52, 23.59],
    },
    BlockPaletteEntry {
        state_id: 2865,
        lab: [44.17, 28.88, 44.47],
    },
    BlockPaletteEntry {
        state_id: 2550,
        lab: [43.79, 34.81, 15.85],
    },
    BlockPaletteEntry {
        state_id: 368,
        lab: [40.73, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 2528,
        lab: [40.73, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 2545,
        lab: [44.47, 28.72, 40.08],
    },
    BlockPaletteEntry {
        state_id: 2864,
        lab: [45.22, 29.55, 44.79],
    },
    BlockPaletteEntry {
        state_id: 2896,
        lab: [45.22, 29.55, 44.79],
    },
    BlockPaletteEntry {
        state_id: 928,
        lab: [42.18, 4.23, 24.01],
    },
    BlockPaletteEntry {
        state_id: 569,
        lab: [43.91, -11.88, -20.34],
    },
    BlockPaletteEntry {
        state_id: 2866,
        lab: [45.74, 29.85, 45.38],
    },
    BlockPaletteEntry {
        state_id: 2592,
        lab: [42.23, 0.48, 6.54],
    },
    BlockPaletteEntry {
        state_id: 193,
        lab: [46.35, 29.29, 44.67],
    },
    BlockPaletteEntry {
        state_id: 48,
        lab: [44.0, 11.74, 22.62],
    },
    BlockPaletteEntry {
        state_id: 528,
        lab: [43.44, 0.61, 4.66],
    },
    BlockPaletteEntry {
        state_id: 464,
        lab: [43.44, 0.61, 4.66],
    },
    BlockPaletteEntry {
        state_id: 2546,
        lab: [45.04, 28.37, -0.93],
    },
    BlockPaletteEntry {
        state_id: 2752,
        lab: [45.38, 20.91, 24.81],
    },
    BlockPaletteEntry {
        state_id: 2004,
        lab: [47.41, 27.96, 36.81],
    },
    BlockPaletteEntry {
        state_id: 84,
        lab: [47.41, 27.96, 36.81],
    },
    BlockPaletteEntry {
        state_id: 736,
        lab: [48.05, 29.2, 26.42],
    },
    BlockPaletteEntry {
        state_id: 32,
        lab: [46.21, 2.04, 25.85],
    },
    BlockPaletteEntry {
        state_id: 720,
        lab: [46.98, 17.3, 15.05],
    },
    BlockPaletteEntry {
        state_id: 692,
        lab: [46.98, 17.3, 15.05],
    },
    BlockPaletteEntry {
        state_id: 562,
        lab: [50.99, 55.22, -39.02],
    },
    BlockPaletteEntry {
        state_id: 2549,
        lab: [47.18, -15.84, 33.63],
    },
    BlockPaletteEntry {
        state_id: 336,
        lab: [47.19, 1.67, -13.87],
    },
    BlockPaletteEntry {
        state_id: 2547,
        lab: [47.34, 7.93, -15.33],
    },
    BlockPaletteEntry {
        state_id: 2552,
        lab: [47.69, 9.69, 9.27],
    },
    BlockPaletteEntry {
        state_id: 1184,
        lab: [47.71, 10.31, 3.91],
    },
    BlockPaletteEntry {
        state_id: 1168,
        lab: [47.71, 10.31, 3.91],
    },
    BlockPaletteEntry {
        state_id: 976,
        lab: [47.64, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 992,
        lab: [47.64, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 256,
        lab: [48.44, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 768,
        lab: [49.03, -9.83, 7.24],
    },
    BlockPaletteEntry {
        state_id: 2003,
        lab: [50.17, 13.39, 25.26],
    },
    BlockPaletteEntry {
        state_id: 83,
        lab: [50.17, 13.39, 25.26],
    },
    BlockPaletteEntry {
        state_id: 1555,
        lab: [49.35, -4.07, 6.63],
    },
    BlockPaletteEntry {
        state_id: 1569,
        lab: [49.35, -4.07, 6.63],
    },
    BlockPaletteEntry {
        state_id: 2720,
        lab: [51.88, 7.62, 54.32],
    },
    BlockPaletteEntry {
        state_id: 1557,
        lab: [50.03, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1571,
        lab: [50.03, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1556,
        lab: [50.03, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1570,
        lab: [50.03, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1424,
        lab: [51.07, 3.7, 30.1],
    },
    BlockPaletteEntry {
        state_id: 17,
        lab: [51.51, 13.23, 14.31],
    },
    BlockPaletteEntry {
        state_id: 693,
        lab: [51.22, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1554,
        lab: [51.22, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1568,
        lab: [51.22, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 64,
        lab: [51.62, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 691,
        lab: [51.62, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1553,
        lab: [51.62, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 18,
        lab: [52.42, 15.02, 16.25],
    },
    BlockPaletteEntry {
        state_id: 2064,
        lab: [52.15, -9.66, 4.73],
    },
    BlockPaletteEntry {
        state_id: 208,
        lab: [52.24, 0.94, 0.95],
    },
    BlockPaletteEntry {
        state_id: 16,
        lab: [52.41, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1552,
        lab: [52.41, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1456,
        lab: [57.67, 23.01, 59.3],
    },
    BlockPaletteEntry {
        state_id: 1376,
        lab: [57.67, 23.01, 59.3],
    },
    BlockPaletteEntry {
        state_id: 2000,
        lab: [55.25, 4.63, 30.68],
    },
    BlockPaletteEntry {
        state_id: 80,
        lab: [55.25, 4.63, 30.68],
    },
    BlockPaletteEntry {
        state_id: 2000,
        lab: [55.25, 4.63, 30.68],
    },
    BlockPaletteEntry {
        state_id: 21,
        lab: [54.76, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 240,
        lab: [54.8, 1.69, 2.43],
    },
    BlockPaletteEntry {
        state_id: 22,
        lab: [55.59, 0.4, -1.07],
    },
    BlockPaletteEntry {
        state_id: 563,
        lab: [57.58, 6.14, -36.03],
    },
    BlockPaletteEntry {
        state_id: 1648,
        lab: [58.37, -15.5, 53.76],
    },
    BlockPaletteEntry {
        state_id: 2548,
        lab: [59.29, 11.88, 56.59],
    },
    BlockPaletteEntry {
        state_id: 896,
        lab: [57.47, -3.36, -2.97],
    },
    BlockPaletteEntry {
        state_id: 224,
        lab: [58.11, -1.63, 8.41],
    },
    BlockPaletteEntry {
        state_id: 561,
        lab: [61.73, 31.5, 48.42],
    },
    BlockPaletteEntry {
        state_id: 565,
        lab: [63.11, -53.24, 49.16],
    },
    BlockPaletteEntry {
        state_id: 291,
        lab: [59.33, -0.95, 5.05],
    },
    BlockPaletteEntry {
        state_id: 2192,
        lab: [60.72, 12.01, 19.93],
    },
    BlockPaletteEntry {
        state_id: 2689,
        lab: [61.51, -23.5, 2.72],
    },
    BlockPaletteEntry {
        state_id: 566,
        lab: [63.52, 31.98, 1.1],
    },
    BlockPaletteEntry {
        state_id: 2688,
        lab: [65.05, -24.68, 3.41],
    },
    BlockPaletteEntry {
        state_id: 564,
        lab: [67.1, -9.87, 61.94],
    },
    BlockPaletteEntry {
        state_id: 568,
        lab: [65.77, -2.14, -0.74],
    },
    BlockPaletteEntry {
        state_id: 1312,
        lab: [67.35, 0.84, -7.31],
    },
    BlockPaletteEntry {
        state_id: 688,
        lab: [68.49, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1264,
        lab: [70.5, 6.31, -45.53],
    },
    BlockPaletteEntry {
        state_id: 1598,
        lab: [71.69, 4.78, 30.08],
    },
    BlockPaletteEntry {
        state_id: 1614,
        lab: [71.69, 4.78, 30.08],
    },
    BlockPaletteEntry {
        state_id: 2640,
        lab: [73.75, -43.08, 41.77],
    },
    BlockPaletteEntry {
        state_id: 2002,
        lab: [73.16, -2.08, 30.83],
    },
    BlockPaletteEntry {
        state_id: 82,
        lab: [73.16, -2.08, 30.83],
    },
    BlockPaletteEntry {
        state_id: 19,
        lab: [73.39, 0.56, -1.52],
    },
    BlockPaletteEntry {
        state_id: 2128,
        lab: [77.67, -58.05, 38.49],
    },
    BlockPaletteEntry {
        state_id: 20,
        lab: [74.5, 0.56, -1.52],
    },
    BlockPaletteEntry {
        state_id: 2544,
        lab: [74.9, 8.93, 12.98],
    },
    BlockPaletteEntry {
        state_id: 304,
        lab: [77.12, -14.94, 54.43],
    },
    BlockPaletteEntry {
        state_id: 2784,
        lab: [78.24, 1.44, -27.96],
    },
    BlockPaletteEntry {
        state_id: 912,
        lab: [80.8, -34.9, -7.81],
    },
    BlockPaletteEntry {
        state_id: 2704,
        lab: [78.37, -11.18, 1.33],
    },
    BlockPaletteEntry {
        state_id: 274,
        lab: [82.71, -0.55, 2.6],
    },
    BlockPaletteEntry {
        state_id: 385,
        lab: [82.96, -5.4, 27.38],
    },
    BlockPaletteEntry {
        state_id: 384,
        lab: [83.59, -5.78, 27.21],
    },
    BlockPaletteEntry {
        state_id: 689,
        lab: [83.59, -5.78, 27.21],
    },
    BlockPaletteEntry {
        state_id: 192,
        lab: [84.06, -5.14, 26.31],
    },
    BlockPaletteEntry {
        state_id: 386,
        lab: [84.44, -5.01, 25.79],
    },
    BlockPaletteEntry {
        state_id: 672,
        lab: [87.41, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 1936,
        lab: [87.68, -10.33, 28.64],
    },
    BlockPaletteEntry {
        state_id: 560,
        lab: [88.47, 0.0, 0.0],
    },
    BlockPaletteEntry {
        state_id: 656,
        lab: [92.0, -12.95, 73.93],
    },
    BlockPaletteEntry {
        state_id: 2481,
        lab: [90.69, -0.04, 4.37],
    },
    BlockPaletteEntry {
        state_id: 2482,
        lab: [90.69, -0.04, 4.37],
    },
    BlockPaletteEntry {
        state_id: 2480,
        lab: [92.4, -0.21, 3.75],
    },
    BlockPaletteEntry {
        state_id: 695,
        lab: [92.4, -0.21, 3.75],
    },
    BlockPaletteEntry {
        state_id: 1280,
        lab: [97.83, -3.6, -1.25],
    },
];

// Representative RGB values from the same frozen palette order as BLOCK_PALETTE.
// These are the colors emitted by mc_do_convert and are the map converter input.
const BLOCK_PALETTE_RGB: [[u8; 3]; 152] = [
    [19, 19, 19],
    [20, 18, 30],
    [26, 22, 22],
    [37, 23, 16],
    [45, 23, 27],
    [45, 23, 27],
    [46, 29, 12],
    [52, 41, 23],
    [61, 40, 18],
    [61, 40, 18],
    [58, 42, 36],
    [70, 43, 27],
    [77, 51, 36],
    [79, 51, 31],
    [171, 28, 9],
    [46, 57, 142],
    [64, 64, 64],
    [53, 71, 27],
    [74, 60, 91],
    [111, 54, 53],
    [39, 67, 138],
    [85, 64, 52],
    [87, 68, 27],
    [151, 52, 49],
    [101, 68, 51],
    [101, 68, 51],
    [143, 61, 47],
    [14, 102, 25],
    [76, 83, 42],
    [60, 88, 75],
    [104, 78, 47],
    [104, 78, 47],
    [118, 70, 86],
    [102, 81, 50],
    [84, 84, 84],
    [127, 62, 182],
    [108, 88, 58],
    [87, 91, 91],
    [119, 86, 59],
    [114, 88, 74],
    [119, 89, 55],
    [125, 85, 80],
    [123, 88, 57],
    [162, 83, 28],
    [162, 78, 79],
    [96, 96, 96],
    [96, 96, 96],
    [162, 84, 38],
    [166, 85, 30],
    [166, 85, 30],
    [119, 96, 60],
    [47, 111, 137],
    [168, 86, 30],
    [105, 99, 89],
    [169, 88, 33],
    [134, 96, 67],
    [107, 102, 95],
    [107, 102, 95],
    [150, 88, 109],
    [151, 93, 67],
    [169, 92, 51],
    [169, 92, 51],
    [170, 93, 71],
    [127, 107, 66],
    [147, 100, 87],
    [147, 100, 87],
    [180, 81, 189],
    [104, 118, 53],
    [102, 112, 135],
    [113, 109, 138],
    [135, 107, 98],
    [133, 107, 107],
    [133, 107, 107],
    [113, 113, 113],
    [113, 113, 113],
    [115, 115, 115],
    [104, 121, 104],
    [154, 110, 77],
    [154, 110, 77],
    [115, 119, 106],
    [115, 119, 106],
    [158, 117, 18],
    [119, 119, 119],
    [119, 119, 119],
    [119, 119, 119],
    [119, 119, 119],
    [144, 118, 70],
    [153, 114, 99],
    [122, 122, 122],
    [122, 122, 122],
    [122, 122, 122],
    [123, 123, 123],
    [123, 123, 123],
    [123, 123, 123],
    [159, 115, 98],
    [110, 129, 116],
    [127, 124, 123],
    [125, 125, 125],
    [125, 125, 125],
    [197, 121, 24],
    [197, 121, 24],
    [157, 128, 79],
    [157, 128, 79],
    [157, 128, 79],
    [131, 131, 131],
    [136, 130, 127],
    [133, 133, 135],
    [107, 138, 201],
    [141, 146, 36],
    [186, 133, 35],
    [129, 140, 143],
    [143, 140, 125],
    [219, 125, 63],
    [66, 174, 57],
    [145, 143, 134],
    [179, 138, 112],
    [100, 160, 143],
    [208, 132, 153],
    [107, 170, 151],
    [177, 166, 39],
    [155, 161, 161],
    [159, 164, 177],
    [167, 167, 167],
    [125, 173, 255],
    [203, 171, 121],
    [203, 171, 121],
    [121, 200, 101],
    [196, 179, 123],
    [196, 179, 123],
    [180, 180, 183],
    [81, 217, 117],
    [183, 183, 186],
    [210, 178, 161],
    [195, 196, 85],
    [165, 195, 245],
    [98, 219, 214],
    [172, 200, 191],
    [207, 206, 201],
    [216, 208, 155],
    [217, 210, 157],
    [217, 210, 157],
    [219, 211, 160],
    [220, 212, 162],
    [219, 219, 219],
    [221, 224, 165],
    [222, 222, 222],
    [249, 236, 79],
    [232, 228, 220],
    [232, 228, 220],
    [236, 233, 226],
    [236, 233, 226],
    [240, 251, 251],
];

#[cfg(test)]
pub(crate) fn convert_rgb24_to_states(
    rgb: &[u8],
    expected_pixels: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u16>, String> {
    convert_rgb24_to_states_with_backend(
        rgb,
        expected_pixels,
        cancellation,
        deadline,
        resolve_render_backend(),
    )
}

pub(crate) fn convert_rgb24_to_states_with_backend(
    rgb: &[u8],
    expected_pixels: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
    requested_backend: RenderBackend,
) -> Result<Vec<u16>, String> {
    if expected_pixels == 0 || expected_pixels > MAX_BLOCK_PIXELS {
        return Err("block video frame exceeds the pixel budget".to_owned());
    }
    if rgb.len() != expected_pixels.saturating_mul(3) {
        return Err("block video RGB frame length is invalid".to_owned());
    }
    let mut output = Vec::with_capacity(expected_pixels);
    convert_palette_indices(
        rgb,
        cancellation,
        deadline,
        requested_backend,
        DispatchComponent::MinecraftBlockPaletteStates,
        "block video",
        |best| {
            output.push(BLOCK_PALETTE[best].state_id);
        },
    )?;
    Ok(output)
}

#[cfg(test)]
pub(crate) fn convert_rgb24_to_palette_rgb(
    rgb: &[u8],
    expected_pixels: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    convert_rgb24_to_palette_rgb_with_backend(
        rgb,
        expected_pixels,
        cancellation,
        deadline,
        resolve_render_backend(),
    )
}

pub(crate) fn convert_rgb24_to_palette_rgb_with_backend(
    rgb: &[u8],
    expected_pixels: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
    requested_backend: RenderBackend,
) -> Result<Vec<u8>, String> {
    if expected_pixels == 0 || expected_pixels > MAX_MAP_VIDEO_PIXELS {
        return Err("map video frame exceeds the block-palette pixel budget".to_owned());
    }
    let expected_bytes = expected_pixels
        .checked_mul(3)
        .ok_or_else(|| "map video RGB frame length overflowed".to_owned())?;
    if rgb.len() != expected_bytes {
        return Err("map video RGB frame length is invalid".to_owned());
    }
    let mut output = Vec::with_capacity(expected_bytes);
    convert_palette_indices(
        rgb,
        cancellation,
        deadline,
        requested_backend,
        DispatchComponent::MinecraftBlockPaletteRgb,
        "map video block-palette",
        |best| output.extend_from_slice(&BLOCK_PALETTE_RGB[best]),
    )?;
    Ok(output)
}

fn convert_palette_indices(
    rgb: &[u8],
    cancellation: &CancellationToken,
    deadline: Instant,
    requested_backend: RenderBackend,
    component: DispatchComponent,
    label: &str,
    mut emit: impl FnMut(usize),
) -> Result<(), String> {
    let dispatcher = BlockPaletteDispatcher::new(requested_backend);
    let checkpoint = |index: usize| -> Result<(), String> {
        if index.is_multiple_of(256) {
            if cancellation.is_cancelled() {
                return Err(format!("{label} conversion cancelled"));
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} conversion deadline exceeded"));
            }
        }
        Ok(())
    };
    checkpoint(0)?;
    dispatch_observer::observe(component, requested_backend, dispatcher.backend);
    match dispatcher.backend {
        RenderBackend::Scalar => {
            for (index, pixel) in rgb.chunks_exact(3).enumerate() {
                checkpoint(index)?;
                emit(nearest_palette_index([pixel[0], pixel[1], pixel[2]]));
            }
        }
        RenderBackend::Avx2Fma => {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                const PIXELS: usize = 8;
                const BYTES: usize = PIXELS * 3;
                let batches = rgb.len() / BYTES;
                for batch in 0..batches {
                    let pixel_offset = batch * PIXELS;
                    checkpoint(pixel_offset)?;
                    let byte_offset = batch * BYTES;
                    // SAFETY: the private dispatcher established AVX2/FMA
                    // support and the slice contains exactly eight pixels.
                    let labs = unsafe {
                        crate::mail_render::rgb24_to_lab_avx2(
                            &rgb[byte_offset..byte_offset + BYTES],
                        )
                    };
                    for lab in labs {
                        // SAFETY: the same validated backend remains active.
                        emit(unsafe { nearest_palette_lab_avx2(lab) });
                    }
                }
                for (lane, pixel) in rgb[batches * BYTES..].chunks_exact(3).enumerate() {
                    checkpoint(batches * PIXELS + lane)?;
                    // SAFETY: the private dispatcher established AVX2/FMA.
                    emit(unsafe {
                        nearest_palette_lab_avx2(crate::mail_render::rgb_to_lab([
                            pixel[0], pixel[1], pixel[2],
                        ]))
                    });
                }
            }
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            unreachable!("AVX2 block palette backend cannot resolve on this target");
        }
        RenderBackend::Avx512 => {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                const PIXELS: usize = 16;
                const BYTES: usize = PIXELS * 3;
                let batches = rgb.len() / BYTES;
                for batch in 0..batches {
                    let pixel_offset = batch * PIXELS;
                    checkpoint(pixel_offset)?;
                    let byte_offset = batch * BYTES;
                    // SAFETY: the private dispatcher established AVX-512F
                    // support and the slice contains exactly sixteen pixels.
                    let labs = unsafe {
                        crate::mail_render::rgb24_to_lab_avx512(
                            &rgb[byte_offset..byte_offset + BYTES],
                        )
                    };
                    for lab in labs {
                        // SAFETY: the same validated backend remains active.
                        emit(unsafe { nearest_palette_lab_avx512(lab) });
                    }
                }
                for (lane, pixel) in rgb[batches * BYTES..].chunks_exact(3).enumerate() {
                    checkpoint(batches * PIXELS + lane)?;
                    // SAFETY: the private dispatcher established AVX-512F.
                    emit(unsafe {
                        nearest_palette_lab_avx512(crate::mail_render::rgb_to_lab([
                            pixel[0], pixel[1], pixel[2],
                        ]))
                    });
                }
            }
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            unreachable!("AVX-512 block palette backend cannot resolve on this target");
        }
    }
    Ok(())
}

fn nearest_palette_index(rgb: [u8; 3]) -> usize {
    let lab = crate::mail_render::rgb_to_lab(rgb);
    let mut best = 0;
    let mut minimum = f32::MAX;
    for (index, entry) in BLOCK_PALETTE.iter().enumerate() {
        let dl = lab[0] - entry.lab[0];
        let da = lab[1] - entry.lab[1];
        let db = lab[2] - entry.lab[2];
        let distance = dl * dl + da * da + db * db;
        if distance < minimum {
            minimum = distance;
            best = index;
        }
    }
    best
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockPaletteSimdCapabilities {
    avx2_fma: bool,
    avx512f: bool,
}

fn host_block_palette_simd_capabilities() -> BlockPaletteSimdCapabilities {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let capabilities = crate::mail_render::host_simd_capabilities();
        BlockPaletteSimdCapabilities {
            avx2_fma: capabilities.avx2 && capabilities.fma,
            avx512f: capabilities.avx512f,
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        BlockPaletteSimdCapabilities {
            avx2_fma: false,
            avx512f: false,
        }
    }
}

fn select_block_palette_backend(
    requested: RenderBackend,
    capabilities: BlockPaletteSimdCapabilities,
) -> RenderBackend {
    match requested {
        RenderBackend::Scalar => RenderBackend::Scalar,
        RenderBackend::Avx2Fma => {
            if capabilities.avx2_fma {
                RenderBackend::Avx2Fma
            } else {
                RenderBackend::Scalar
            }
        }
        RenderBackend::Avx512 => {
            if capabilities.avx512f {
                RenderBackend::Avx512
            } else if capabilities.avx2_fma {
                RenderBackend::Avx2Fma
            } else {
                RenderBackend::Scalar
            }
        }
    }
}

#[derive(Clone, Copy)]
struct BlockPaletteDispatcher {
    backend: RenderBackend,
}

impl BlockPaletteDispatcher {
    fn new(requested_backend: RenderBackend) -> Self {
        Self {
            backend: select_block_palette_backend(
                requested_backend,
                host_block_palette_simd_capabilities(),
            ),
        }
    }

    #[cfg(test)]
    fn nearest(self, rgb: [u8; 3]) -> usize {
        match self.backend {
            RenderBackend::Scalar => nearest_palette_index(rgb),
            RenderBackend::Avx2Fma => {
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                {
                    // SAFETY: the private dispatcher can only be constructed by
                    // revalidating OS-aware AVX2/FMA support on this host.
                    unsafe { nearest_palette_index_avx2(rgb) }
                }
                #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                {
                    nearest_palette_index(rgb)
                }
            }
            RenderBackend::Avx512 => {
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                {
                    // SAFETY: the private dispatcher can only be constructed by
                    // revalidating OS-aware AVX-512F support on this host.
                    unsafe { nearest_palette_index_avx512(rgb) }
                }
                #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                {
                    nearest_palette_index(rgb)
                }
            }
        }
    }
}

#[cfg(test)]
fn nearest_palette_index_dispatch(rgb: [u8; 3], requested_backend: RenderBackend) -> usize {
    BlockPaletteDispatcher::new(requested_backend).nearest(rgb)
}

struct BlockPaletteComponents {
    l: [f32; 152],
    a: [f32; 152],
    b: [f32; 152],
}

fn block_palette_components() -> &'static BlockPaletteComponents {
    static COMPONENTS: OnceLock<BlockPaletteComponents> = OnceLock::new();
    COMPONENTS.get_or_init(|| BlockPaletteComponents {
        l: std::array::from_fn(|index| BLOCK_PALETTE[index].lab[0]),
        a: std::array::from_fn(|index| BLOCK_PALETTE[index].lab[1]),
        b: std::array::from_fn(|index| BLOCK_PALETTE[index].lab[2]),
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg(test)]
#[target_feature(enable = "avx2,fma")]
unsafe fn nearest_palette_index_avx2(rgb: [u8; 3]) -> usize {
    // SAFETY: this function's target feature contract is identical to the Lab
    // kernel's contract.
    unsafe { nearest_palette_lab_avx2(crate::mail_render::rgb_to_lab(rgb)) }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,fma")]
unsafe fn nearest_palette_lab_avx2(lab: [f32; 3]) -> usize {
    use std::arch::x86_64::*;
    let components = block_palette_components();
    let query_l = _mm256_set1_ps(lab[0]);
    let query_a = _mm256_set1_ps(lab[1]);
    let query_b = _mm256_set1_ps(lab[2]);
    let mut best = 0;
    let mut minimum = f32::MAX;
    let vector_end = BLOCK_PALETTE.len() / 8 * 8;
    for offset in (0..vector_end).step_by(8) {
        // SAFETY: `offset` advances only across complete eight-lane ranges in
        // each fixed 152-entry component array.
        let distance = unsafe {
            let dl = _mm256_sub_ps(query_l, _mm256_loadu_ps(components.l.as_ptr().add(offset)));
            let da = _mm256_sub_ps(query_a, _mm256_loadu_ps(components.a.as_ptr().add(offset)));
            let db = _mm256_sub_ps(query_b, _mm256_loadu_ps(components.b.as_ptr().add(offset)));
            _mm256_add_ps(
                _mm256_add_ps(_mm256_mul_ps(dl, dl), _mm256_mul_ps(da, da)),
                _mm256_mul_ps(db, db),
            )
        };
        let mut distances = [0.0_f32; 8];
        // SAFETY: `distances` has exactly eight f32 slots for this store.
        unsafe { _mm256_storeu_ps(distances.as_mut_ptr(), distance) };
        for (index, distance) in distances.into_iter().enumerate() {
            if distance < minimum {
                minimum = distance;
                best = offset + index;
            }
        }
    }
    for (index, &entry) in BLOCK_PALETTE.iter().enumerate().skip(vector_end) {
        let dl = lab[0] - entry.lab[0];
        let da = lab[1] - entry.lab[1];
        let db = lab[2] - entry.lab[2];
        let distance = dl * dl + da * da + db * db;
        if distance < minimum {
            minimum = distance;
            best = index;
        }
    }
    best
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg(test)]
#[target_feature(enable = "avx512f")]
unsafe fn nearest_palette_index_avx512(rgb: [u8; 3]) -> usize {
    // SAFETY: this function's target feature contract is identical to the Lab
    // kernel's contract.
    unsafe { nearest_palette_lab_avx512(crate::mail_render::rgb_to_lab(rgb)) }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[target_feature(enable = "avx512f")]
unsafe fn nearest_palette_lab_avx512(lab: [f32; 3]) -> usize {
    use std::arch::x86_64::*;
    let components = block_palette_components();
    let query_l = _mm512_set1_ps(lab[0]);
    let query_a = _mm512_set1_ps(lab[1]);
    let query_b = _mm512_set1_ps(lab[2]);
    let mut best = 0;
    let mut minimum = f32::MAX;
    let vector_end = BLOCK_PALETTE.len() / 16 * 16;
    for offset in (0..vector_end).step_by(16) {
        // SAFETY: `offset` advances only across complete sixteen-lane ranges
        // in each fixed 152-entry component array.
        let distance = unsafe {
            let dl = _mm512_sub_ps(query_l, _mm512_loadu_ps(components.l.as_ptr().add(offset)));
            let da = _mm512_sub_ps(query_a, _mm512_loadu_ps(components.a.as_ptr().add(offset)));
            let db = _mm512_sub_ps(query_b, _mm512_loadu_ps(components.b.as_ptr().add(offset)));
            _mm512_add_ps(
                _mm512_add_ps(_mm512_mul_ps(dl, dl), _mm512_mul_ps(da, da)),
                _mm512_mul_ps(db, db),
            )
        };
        let mut distances = [0.0_f32; 16];
        // SAFETY: `distances` has exactly sixteen f32 slots for this store.
        unsafe { _mm512_storeu_ps(distances.as_mut_ptr(), distance) };
        for (index, distance) in distances.into_iter().enumerate() {
            if distance < minimum {
                minimum = distance;
                best = offset + index;
            }
        }
    }
    for (index, &entry) in BLOCK_PALETTE.iter().enumerate().skip(vector_end) {
        let dl = lab[0] - entry.lab[0];
        let da = lab[1] - entry.lab[1];
        let db = lab[2] - entry.lab[2];
        let distance = dl * dl + da * da + db * db;
        if distance < minimum {
            minimum = distance;
            best = index;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_palette_has_all_entries_and_never_maps_to_air() {
        assert_eq!(BLOCK_PALETTE.len(), 152);
        assert_eq!(BLOCK_PALETTE_RGB.len(), BLOCK_PALETTE.len());
        assert!(BLOCK_PALETTE.iter().all(|entry| entry.state_id != 0));
    }

    #[test]
    fn palette_component_arrays_preserve_frozen_candidate_order() {
        let components = block_palette_components();
        for (index, entry) in BLOCK_PALETTE.iter().enumerate() {
            assert_eq!(
                [
                    components.l[index],
                    components.a[index],
                    components.b[index],
                ],
                entry.lab
            );
        }
    }

    #[test]
    fn representative_rgb_conversion_matches_the_frozen_native_palette() {
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let input = [19, 19, 19, 240, 251, 251];
        assert_eq!(
            convert_rgb24_to_palette_rgb(&input, 2, &cancellation, deadline).unwrap(),
            input
        );
        assert_eq!(
            convert_rgb24_to_states(&input, 2, &cancellation, deadline).unwrap(),
            [2768, 1280]
        );
    }

    #[test]
    fn unsupported_requested_backends_have_deterministic_fallbacks() {
        let none = BlockPaletteSimdCapabilities {
            avx2_fma: false,
            avx512f: false,
        };
        let avx2_only = BlockPaletteSimdCapabilities {
            avx2_fma: true,
            avx512f: false,
        };
        assert_eq!(
            select_block_palette_backend(RenderBackend::Avx2Fma, none),
            RenderBackend::Scalar
        );
        assert_eq!(
            select_block_palette_backend(RenderBackend::Avx512, none),
            RenderBackend::Scalar
        );
        assert_eq!(
            select_block_palette_backend(RenderBackend::Avx512, avx2_only),
            RenderBackend::Avx2Fma
        );
    }

    #[test]
    fn every_requested_backend_matches_scalar_on_this_host() {
        let capabilities = host_block_palette_simd_capabilities();
        for requested in [
            RenderBackend::Scalar,
            RenderBackend::Avx2Fma,
            RenderBackend::Avx512,
        ] {
            let dispatcher = BlockPaletteDispatcher::new(requested);
            assert_eq!(
                dispatcher.backend,
                select_block_palette_backend(requested, capabilities)
            );
            for value in 0..4096_u32 {
                let rgb = [
                    (value & 0xff) as u8,
                    ((value >> 4) & 0xff) as u8,
                    ((value >> 8) & 0xff) as u8,
                ];
                let scalar = nearest_palette_index_dispatch(rgb, RenderBackend::Scalar);
                assert_eq!(
                    scalar,
                    dispatcher.nearest(rgb),
                    "palette mismatch for {rgb:?} with {requested:?}"
                );
            }
        }
    }

    #[test]
    fn explicit_backend_conversion_matches_scalar_and_auto() {
        let cancellation = CancellationToken::new();
        let mut input = Vec::with_capacity(64 * 3);
        for value in 0..64_u8 {
            input.extend_from_slice(&[
                value.wrapping_mul(17),
                value.wrapping_mul(73).wrapping_add(11),
                value.wrapping_mul(151).wrapping_add(29),
            ]);
        }
        let convert = |backend| {
            convert_rgb24_to_states_with_backend(
                &input,
                64,
                &cancellation,
                Instant::now() + std::time::Duration::from_secs(2),
                backend,
            )
            .unwrap()
        };
        let scalar = convert(RenderBackend::Scalar);
        assert_eq!(convert(RenderBackend::Avx2Fma), scalar);
        assert_eq!(convert(RenderBackend::Avx512), scalar);
        assert_eq!(
            convert_rgb24_to_states(
                &input,
                64,
                &cancellation,
                Instant::now() + std::time::Duration::from_secs(2),
            )
            .unwrap(),
            scalar
        );

        let convert_palette_rgb = |backend| {
            convert_rgb24_to_palette_rgb_with_backend(
                &input,
                64,
                &cancellation,
                Instant::now() + std::time::Duration::from_secs(2),
                backend,
            )
            .unwrap()
        };
        let scalar_palette_rgb = convert_palette_rgb(RenderBackend::Scalar);
        assert_eq!(
            convert_palette_rgb(RenderBackend::Avx2Fma),
            scalar_palette_rgb
        );
        assert_eq!(
            convert_palette_rgb(RenderBackend::Avx512),
            scalar_palette_rgb
        );
        assert_eq!(
            convert_rgb24_to_palette_rgb(
                &input,
                64,
                &cancellation,
                Instant::now() + std::time::Duration::from_secs(2),
            )
            .unwrap(),
            scalar_palette_rgb
        );
    }

    #[test]
    fn duplicate_palette_colors_keep_first_entry_tie_breaking() {
        assert_eq!(BLOCK_PALETTE[4].lab, BLOCK_PALETTE[5].lab);
        assert_eq!(BLOCK_PALETTE_RGB[4], BLOCK_PALETTE_RGB[5]);
        for requested in [
            RenderBackend::Scalar,
            RenderBackend::Avx2Fma,
            RenderBackend::Avx512,
        ] {
            let index = nearest_palette_index_dispatch(BLOCK_PALETTE_RGB[4], requested);
            assert_eq!(index, 4, "tie changed for {requested:?}");
            assert_eq!(BLOCK_PALETTE[index].state_id, 1792);
        }
    }

    #[test]
    fn explicit_backend_conversion_enforces_frame_boundaries() {
        let cancellation = CancellationToken::new();
        let convert = |rgb: &[u8], pixels| {
            convert_rgb24_to_states_with_backend(
                rgb,
                pixels,
                &cancellation,
                Instant::now() + std::time::Duration::from_secs(1),
                RenderBackend::Avx512,
            )
        };
        assert_eq!(
            convert(&[], 0).unwrap_err(),
            "block video frame exceeds the pixel budget"
        );
        assert_eq!(
            convert(&[], MAX_BLOCK_PIXELS + 1).unwrap_err(),
            "block video frame exceeds the pixel budget"
        );
        assert_eq!(
            convert(&[0, 0], 1).unwrap_err(),
            "block video RGB frame length is invalid"
        );
        assert_eq!(convert(&[0, 0, 0], 1).unwrap().len(), 1);
    }
}
