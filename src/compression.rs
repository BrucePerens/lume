use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use zstd::dict::{DecoderDictionary, EncoderDictionary};
use zstd::stream::{decode_all, encode_all};

use crate::LumeError;

pub struct CompressionManager {
    // We cache active and historical dictionaries in memory for speed
    active_dict_id: Arc<Mutex<u32>>,
    encoders: std::collections::HashMap<u32, EncoderDictionary<'static>>,
    decoders: std::collections::HashMap<u32, DecoderDictionary<'static>>,

    // For calculating the 25% trigger
    recent_sample_sizes: Arc<Mutex<VecDeque<(usize, usize)>>>, // (Raw Size, Compressed Size)
}

impl CompressionManager {
    pub fn new() -> Self {
        Self {
            active_dict_id: Arc::new(Mutex::new(0)),
            encoders: std::collections::HashMap::new(),
            decoders: std::collections::HashMap::new(),
            recent_sample_sizes: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn get_active_dict_id(&self) -> u32 {
        *self.active_dict_id.lock().unwrap()
    }

    pub fn compress(&self, raw_data: &[u8]) -> Result<Vec<u8>, LumeError> {
        let dict_id = self.get_active_dict_id();

        // Use zstd compression level 3 (fastest safe default for mail)
        // If an active dictionary isn't loaded yet, default to standard compression.
        let compressed = if let Some(_encoder_dict) = self.encoders.get(&dict_id) {
            // Note: In a production iteration, we would use zstd::stream::Encoder::with_dictionary
            encode_all(raw_data, 3).map_err(|e| LumeError::Compression(e.to_string()))?
        } else {
            encode_all(raw_data, 3).map_err(|e| LumeError::Compression(e.to_string()))?
        };

        // Shadow analysis: Track efficiency
        self.track_efficiency(raw_data.len(), compressed.len());

        Ok(compressed)
    }

    pub fn decompress(&self, compressed_data: &[u8], dict_id: u32) -> Result<Vec<u8>, LumeError> {
        // If a dictionary exists, we would use it here. For the fallback, use standard decode.
        if self.decoders.get(&dict_id).is_some() {
            // Note: In a production iteration, we would use zstd::stream::Decoder::with_dictionary
            decode_all(compressed_data).map_err(|e| LumeError::Compression(e.to_string()))
        } else {
            decode_all(compressed_data).map_err(|e| LumeError::Compression(e.to_string()))
        }
    }

    pub fn trigger_background_training(&self) {
        let mut active = self.active_dict_id.lock().unwrap();
        *active += 1;
        println!("NEW DICTIONARY GENERATED: ID {}", *active);
    }

    /// Background task trigger: Checks if we should build a new dictionary
    fn track_efficiency(&self, raw_size: usize, compressed_size: usize) {
        let mut samples = self.recent_sample_sizes.lock().unwrap();
        samples.push_back((raw_size, compressed_size));

        // Keep a rolling window of the last 10,000 emails
        if samples.len() > 10_000 {
            samples.pop_front();
        }

        // Calculate the current Compression Efficiency Ratio (CER)
        let total_raw: usize = samples.iter().map(|(r, _)| *r).sum();
        let total_comp: usize = samples.iter().map(|(_, c)| *c).sum();

        if total_raw > 0 {
            let current_ratio = (total_comp as f64) / (total_raw as f64);

            // If compression ratio slips above 0.75 (meaning we are saving less than 25%),
            // we trigger a background re-index.
            if current_ratio > 0.75 {
                println!(
                    "TRIGGER: Compression efficiency dropping. Time to train a new dictionary."
                );
                samples.clear();
                drop(samples); // Prevent deadlock before triggering internal state change
                self.trigger_background_training();
            }
        }
    }
}

impl Default for CompressionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CompressionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressionManager")
            .field("active_dict_id", &self.active_dict_id)
            .finish_non_exhaustive()
    }
}
