use super::ProxyStream;

use tokio::io::AsyncReadExt;
use worker::*;

impl <'a> ProxyStream<'a> {
    pub async fn process_shadowsocks(&mut self) -> Result<()> {
        // 1. Baca port dan alamat tujuan dari header Shadowsocks
        // Ini akan mendapatkan 83.142.30.4
        let remote_addr = crate::common::parse_addr(self).await?;
        
        // Ini akan mendapatkan 2096
        let remote_port = {
            let mut port = [0u8; 2];
            self.read_exact(&mut port).await?;
            ((port[0] as u16) << 8) | (port[1] as u16)
        };
        
        // Asumsi ini adalah koneksi TCP (seperti yang kamu definisikan)
        let is_tcp = true; 
        
        if is_tcp {
            // **PERBAIKAN UTAMA:**
            // Dalam mode Shadowsocks, kita HANYA perlu menyambung ke alamat tujuan
            // yang diekstrak dari header paket (remote_addr:remote_port).
            // Upaya koneksi ke self.config.proxy_addr (yang menyebabkan error :55554) dihapus.
            
            let target_addr = remote_addr;
            let target_port = remote_port;

            // Langsung tangani koneksi TCP keluar ke alamat tujuan yang valid
            if let Err(e) = self.handle_tcp_outbound(target_addr, target_port).await {
                // Log error jika ada masalah saat koneksi ke 83.142.30.4:2096
                console_error!("error handling tcp: Error: {}", e)
            }
        } else {
            // Logika untuk penanganan UDP
            if let Err(e) = self.handle_udp_outbound().await {
                console_error!("error handling udp: {}", e)
            }
        }

        Ok(())
    }
}
