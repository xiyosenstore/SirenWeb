use super::ProxyStream;

use tokio::io::AsyncReadExt;
use worker::*;

impl <'a> ProxyStream<'a> {
    pub async fn process_trojan(&mut self) -> Result<()> {
        // ignore user_id (56 bytes password hash)
        let mut _user_id = [0u8; 56];
        self.read_exact(&mut _user_id).await?;

        // remove crlf (0x0D 0x0A)
        self.read_u16().await?;
        
        // read instruction (CMD)
        let network_type = self.read_u8().await?;
        let is_tcp = network_type == 1;

        // read address
        let remote_addr = crate::common::parse_addr(self).await?;
        
        // read port
        let remote_port = {
            let mut port = [0u8; 2];
            self.read_exact(&mut port).await?;
            ((port[0] as u16) << 8) | (port[1] as u16)
        };

        // remove crlf (0x0D 0x0A)
        self.read_u16().await?;

        if is_tcp {
            // **PERBAIKAN KRUSIAL:** Hapus logika addr_pool dan koneksi ganda.
            // Kita hanya menyambungkan ke alamat tujuan yang sah (remote_addr:remote_port).
            let target_addr = remote_addr;
            let target_port = remote_port;
            
            if let Err(e) = self.handle_tcp_outbound(target_addr, target_port).await {
                console_error!("error handling trojan tcp outbound: {}", e)
            }
        } else {
            if let Err(e) = self.handle_udp_outbound().await {
                console_error!("error handling trojan udp outbound: {}", e)
            }
        }

        Ok(())
    }
}
