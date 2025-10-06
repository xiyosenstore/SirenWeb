// --- Deklarasi Modul Kritis yang Hilang ---
// Ini memberitahu compiler bahwa file-file .rs ini harus dihubungkan.
mod hash;
mod vmess;
mod vless;
mod trojan;
mod shadowsocks;
mod conn;
// ------------------------------------------

mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use std::collections::HashMap;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());

// Base URL for GitHub raw content
static GITHUB_BASE_URL: &str = "https://raw.githubusercontent.com/xiyosenstore/SirenWeb/refs/heads/master/web";

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    // Pastikan UUID di-parse dengan aman.
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    
    // Pastikan variabel environment ada (menggunakan `?` untuk early return Error jika tidak ada)
    let main_page_url = env.var("MAIN_PAGE_URL")?.to_string();
    let sub_page_url = env.var("SUB_PAGE_URL")?.to_string();
    let link_page_url = env.var("LINK_PAGE_URL")?.to_string();

    let config = Config { 
        uuid, 
        proxy_addr: host, // Default: Host Worker Anda
        proxy_port: 443,  // Default: Port 443
        main_page_url, 
        sub_page_url,
        link_page_url,
    };


    let url = req.url()?;
    let path = url.path();

    // Rute aset statis
    if path.starts_with("/css/") {
        return handle_css_file(req).await;
    } else if path.starts_with("/js/") {
        return handle_js_file(req).await;
    } else if path.starts_with("/images/") {
        return handle_image_file(req).await;
    }

    // Rute utama (Router)
    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on_async("/link", link)
        .on_async("/:proxyip", tunnel)
        .on_async("/Benxx-Project/:proxyip", tunnel)
        .run(req, env)
        .await
}

async fn handle_css_file(req: Request) -> Result<Response> {
    let url = req.url()?;
    let filename = url.path().strip_prefix("/css/").unwrap_or("");
    let css_url = format!("{}/css/{}", GITHUB_BASE_URL, filename);
    let req = Fetch::Url(Url::parse(&css_url)?);
    let mut res = req.send().await?;

    if res.status_code() == 200 {
        let css = res.text().await?;
        let mut headers = Headers::new();
        headers.set("Content-Type", "text/css")?;
        headers.set("Cache-Control", "public, max-age=86400")?;
        Ok(Response::ok(css)?.with_headers(headers))
    } else {
        Response::error("CSS file not found", 404)
    }
}

async fn handle_js_file(req: Request) -> Result<Response> {
    let url = req.url()?;
    let filename = url.path().strip_prefix("/js/").unwrap_or("");
    let js_url = format!("{}/js/{}", GITHUB_BASE_URL, filename);
    let req = Fetch::Url(Url::parse(&js_url)?);
    let mut res = req.send().await?;

    if res.status_code() == 200 {
        let js = res.text().await?;
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/javascript")?;
        headers.set("Cache-Control", "public, max-age=86400")?;
        Ok(Response::ok(js)?.with_headers(headers))
    } else {
        Response::error("JavaScript file not found", 404)
    }
}

async fn handle_image_file(req: Request) -> Result<Response> {
    let url = req.url()?;
    let filename = url.path().strip_prefix("/images/").unwrap_or("");
    let image_url = format!("{}/images/{}", GITHUB_BASE_URL, filename);
    let req = Fetch::Url(Url::parse(&image_url)?);
    let mut res = req.send().await?;

    if res.status_code() == 200 {
        let image_data = res.bytes().await?;
        let mut headers = Headers::new();

        if filename.ends_with(".png") {
            headers.set("Content-Type", "image/png")?;
        } else if filename.ends_with(".jpg") || filename.ends_with(".jpeg") {
            headers.set("Content-Type", "image/jpeg")?;
        } else if filename.ends_with(".svg") {
            headers.set("Content-Type", "image/svg+xml")?;
        } else if filename.ends_with(".gif") {
            headers.set("Content-Type", "image/gif")?;
        } else {
            headers.set("Content-Type", "application/octet-stream")?;
        }

        headers.set("Cache-Control", "public, max-age=86400")?;
        Ok(Response::from_bytes(image_data)?.with_headers(headers))
    } else {
        Response::error("Image file not found", 404)
    }
}

async fn get_response_from_url(url: String) -> Result<Response> {
    let req = Fetch::Url(Url::parse(url.as_str())?);
    let mut res = req.send().await?;
    Response::from_html(res.text().await?)
}

async fn fe(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.main_page_url.clone()).await
}

async fn sub(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.sub_page_url.clone()).await
}

async fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.link_page_url.clone()).await
}

async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").unwrap().to_string();
    
    // Logic untuk memilih proxy dari KV storage
    if PROXYKV_PATTERN.is_match(&proxyip) {
        let kvid_list: Vec<String> = proxyip.split(',').map(|s| s.to_string()).collect();
        let kv = cx.kv("SIREN")?;
        
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default();
        
        let mut rand_buf = [0u8; 1];
        // Menggunakan worker::getrandom::getrandom()
        worker::getrandom::getrandom(&mut rand_buf).expect("failed generating random number");

        if proxy_kv_str.is_empty() {
            console_log!("getting proxy kv from github...");
            let req = Fetch::Url(Url::parse("https://siren.cloudaccess.host/best-latency.json")?);
            let mut res = req.send().await?;
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?;
                // Set TTL selama 24 jam
                kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(60 * 60 * 24).execute().await?;
            } else {
                return Err(Error::from(format!("error getting proxy kv: status code {}", res.status_code())));
            }
        }

        // Deserialisasi JSON ke HashMap.
        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)
            .map_err(|e| Error::RustError(format!("Failed to parse proxy KV JSON: {}", e)))?;

        // Mengambil KV ID dan IP/Port secara acak
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        let selected_kv_id = &kvid_list[kv_index];

        match proxy_kv.get(selected_kv_id) {
            Some(ips) => {
                let proxyip_index = (rand_buf[0] as usize) % ips.len();
                // Mengganti ':' menjadi '-' agar sesuai dengan PROXYIP_PATTERN
                proxyip = ips[proxyip_index].clone().replace(':', '-');
            },
            None => {
                console_error!("Selected KV ID '{}' not found in proxy list.", selected_kv_id);
                // Jika tidak ditemukan, lanjutkan menggunakan proxyip default dari URL
            }
        }
    }

    // Logic untuk mengupdate proxy_addr dan proxy_port di Config
    if PROXYIP_PATTERN.is_match(&proxyip) {
        if let Some((addr, port_str)) = proxyip.split_once('-') {
            if let Ok(port) = port_str.parse() {
                // Config diubah, tetapi sekarang ini hanya digunakan sebagai nilai default
                // dan tidak akan menyebabkan koneksi ganda.
                cx.data.proxy_addr = addr.to_string();
                cx.data.proxy_port = port;
            }
        }
    }

    // Penanganan WebSocket (Core Tunneling Logic)
    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade.eq_ignore_ascii_case("websocket") {
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        // Panggil ProxyStream::new dengan Config yang sudah diperbarui
        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            // Semua logika koneksi ada di dalam process(), yang sekarang sudah aman
            if let Err(e) = ProxyStream::new(cx.data, &server, events).process().await {
                console_log!("[tunnel error]: {}", e);
            }
        });

        Response::from_websocket(client)
    } else {
        // Jika bukan WebSocket, kembalikan response default
        Response::from_html("hi from wasm!")
    }
}
