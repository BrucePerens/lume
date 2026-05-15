use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use zstd::dict::{DecoderDictionary, EncoderDictionary};
use zstd::stream::{encode_all, decode_all};

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
    pub fn compress(&self, raw_data: &[u8]) -> Result<Vec<u8>, LumeError> {
        let dict_id = *self.active_dict_id.lock().unwrap();
        let _encoder_dict = self.encoders.get(&dict_id)
            .ok_or_else(|| LumeError::Compression("Active dictionary missing".into()))?;
        
        // Use zstd compression level 3 (fastest safe default for mail)
        let compressed = encode_all(raw_data, 3)
            .map_err(|e| LumeError::Compression(e.to_string()))?;
        
        // Shadow analysis: Track efficiency
        self.track_efficiency(raw_data.len(), compressed.len());
        
        Ok(compressed)
    }

    pub fn decompress(&self, compressed_data: &[u8], dict_id: u32) -> Result<Vec<u8>, LumeError> {
        let _decoder_dict = self.decoders.get(&dict_id)
            .ok_or_else(|| LumeError::Compression(format!("Dictionary v{} not found", dict_id)))?;
        
        let decompressed = decode_all(compressed_data)
            .map_err(|e| LumeError::Compression(e.to_string()))?;
            
        Ok(decompressed)
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
        let total_raw: usize = samples.iter().map(|(r, _)| r).sum();
        let total_comp: usize = samples.iter().map(|(_, c)| c).sum();
        
        if total_raw > 0 {
            let current_ratio = (total_comp as f64) / (total_raw as f64);
            
            // If compression ratio slips above 0.75 (meaning we are saving less than 25%),
            // we trigger a background re-index.
            // (In a real system, this would push a message to an async worker queue)
            if current_ratio > 0.75 {
                println!("TRIGGER: Compression efficiency dropping. Time to train a new dictionary.");
                // self.trigger_background_training();
            }
        }
    }
}
