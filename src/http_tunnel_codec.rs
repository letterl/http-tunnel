/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use std::fmt::Write;
use async_trait::async_trait;
use bytes::BytesMut;
use log::debug;
use regex::Regex;
use tokio::io::{Error, ErrorKind};
use tokio_util::codec::{Decoder, Encoder};
use base64::decode;
use std::str;

use crate::tunnel::{EstablishTunnelResult, TunnelCtx, TunnelTarget};
use core::fmt;

const REQUEST_END_MARKER: &[u8] = b"\r\n\r\n";
/// A reasonable value to limit possible header size
/// as long as we only need to support `CONNECT` requests.
const MAX_HTTP_REQUEST_SIZE: usize = 1024;

/// HTTP/1.1 request representation
/// Supports only `CONNECT` method
pub struct HttpConnectRequest {
    uri: String,
    // out of scope of this demo, but let's put it here for extensibility
    // e.g. Authorization/Policies headers
    // headers: Vec<(String, String)>,
}

#[derive(Builder, Eq, PartialEq, Debug, Clone)]
pub struct HttpTunnelTarget {
    pub target: String,
    // easily can be extended with something like
    // policies: Vec<TunnelPolicy>
}

/// Codec to extract `HTTP/1.1 CONNECT` requests and build a corresponding `HTTP` response.
#[derive(Clone, Builder)]
pub struct HttpTunnelCodec {
    tunnel_ctx: TunnelCtx,
    enabled_targets: Regex,
}

impl Decoder for HttpTunnelCodec {
    type Item = HttpTunnelTarget;
    type Error = EstablishTunnelResult;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !got_http_request(&src) {
            return Ok(None);
        }

        match HttpConnectRequest::parse(&src) {
            Ok(parsed_request) => {
                if !self.enabled_targets.is_match(&parsed_request.uri) {
                    debug!(
                        "Target `{}` is not allowed. Allowed: `{}`, CTX={}",
                        parsed_request.uri, self.enabled_targets, self.tunnel_ctx
                    );
                    Err(EstablishTunnelResult::Forbidden)
                } else {
                    Ok(Some(
                        HttpTunnelTargetBuilder::default()
                            .target(parsed_request.uri)
                            .build()
                            .expect("HttpTunnelTargetBuilder failed"),
                    ))
                }
            }
            Err(e) => Err(e),
        }
    }
}

impl Encoder<EstablishTunnelResult> for HttpTunnelCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: EstablishTunnelResult,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let (code, message) = match item {
            EstablishTunnelResult::Ok => (200, "Connection established\r\nConnection:keep-alive"),
            EstablishTunnelResult::BadRequest => (400, "BAD_REQUEST"),
            EstablishTunnelResult::Forbidden => (403, "FORBIDDEN"),
            EstablishTunnelResult::OperationNotAllowed => (405, "NOT_ALLOWED"),
            EstablishTunnelResult::RequestTimeout => (408, "TIMEOUT"),
            EstablishTunnelResult::TooManyRequests => (429, "TOO_MANY_REQUESTS"),
            EstablishTunnelResult::ServerError => (500, "SERVER_ERROR"),
            EstablishTunnelResult::BadGateway => (502, "BAD_GATEWAY"),
            EstablishTunnelResult::GatewayTimeout => (504, "GATEWAY_TIMEOUT"),
        };

        dst.write_fmt(format_args!("HTTP/1.1 {} {}\r\n\r\n", code as u32, message))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))
    }
}

#[async_trait]
impl TunnelTarget for HttpTunnelTarget {
    type Addr = String;

    fn target_addr(&self) -> Self::Addr {
        self.target.clone()
    }
}

// cov:begin-ignore-line
impl fmt::Display for HttpTunnelTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.target)
    }
}
// cov:end-ignore-line

fn got_http_request(buffer: &BytesMut) -> bool {
    buffer.len() >= MAX_HTTP_REQUEST_SIZE || buffer.ends_with(REQUEST_END_MARKER)
}

impl From<Error> for EstablishTunnelResult {
    fn from(e: Error) -> Self {
        match e.kind() {
            ErrorKind::TimedOut => EstablishTunnelResult::GatewayTimeout,
            _ => EstablishTunnelResult::BadGateway,
        }
    }
}

/// Basic HTTP Request parser which only purpose is to parse `CONNECT` requests.
impl HttpConnectRequest {   
    pub fn parse(http_request: &[u8]) -> Result<Self, EstablishTunnelResult> {

        HttpConnectRequest::precondition_size(http_request)?;
        HttpConnectRequest::precondition_legal_characters(http_request)?;
        let a= HttpConnectRequest::http_obs(http_request)?;
        let s = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", a, a);
        let mut lines = s.split("\r\n");
        let request_line = HttpConnectRequest::parse_request_line(
            lines
                .next()
                .expect("At least a single line is present at this point"),
        )?;


        Ok(Self {
            uri: request_line.1.to_string(),
            // headers: vec![], // if we want to add headers
        })
    }


   pub fn data_xor<'a>(sub: u8, buf: &'a mut [u8]) -> Result<u8, EstablishTunnelResult> {
        let password = b"123456";
        let mut pasub = sub;
        for i in 0..buf.len() {
            buf[i] ^= password[pasub as usize] | pasub;
            pasub = pasub+1;
            if pasub == password.len() as u8{
                pasub=0;
            }
        }
        if buf.len() == 0 {
            Err(EstablishTunnelResult::BadRequest)
        } else {
            Ok(pasub)
        }
    }

    
    fn http_obs(http_request: &[u8]) -> Result<String, EstablishTunnelResult>{
        let http = String::from_utf8_lossy(http_request).into_owned();
        let re = Regex::new(r"(: )(.+=)").unwrap();
        let mut host="CR0LGQ0ZCQkGBDU=".to_string();
        match re.captures(&http){
            Some(value) => {
                host= value.get(2).map_or("", |m| m.as_str()).to_string();
            }
            None => {}
        }

        let password = b"123456";
        let mut bytes = decode(host.as_bytes()).unwrap();
        let mut pasub:u8=0;
        for i in 0..bytes.len() {
            bytes[i] ^= password[pasub as usize] | pasub;
            pasub = pasub+1;
            if pasub == password.len() as u8{
                pasub=0;
            }
        }
        //修改解析的值
        let s=String::from_utf8_lossy(&bytes).trim_matches(char::from(0)).to_string();
        if host.len() == 0 {
            Err(EstablishTunnelResult::BadRequest)
        } else {
            Ok(s)
        }
    }

    fn parse_request_line(request_line: &str) -> Result<(&str, &str, &str), EstablishTunnelResult> {
        let request_line_items = request_line.split(' ').collect::<Vec<&str>>();
        HttpConnectRequest::precondition_well_formed(request_line, &request_line_items)?;

        let method = request_line_items[0];
        let uri = request_line_items[1];
        let version = request_line_items[2];

        HttpConnectRequest::check_method(method)?;
        HttpConnectRequest::check_version(version)?;

        Ok((method, uri, version))
    }

    fn precondition_well_formed(
        request_line: &str,
        request_line_items: &[&str],
    ) -> Result<(), EstablishTunnelResult> {
        if request_line_items.len() != 3 {
            debug!("Bad request line: `{:?}`", request_line,);
            Err(EstablishTunnelResult::BadRequest)
        } else {
            Ok(())
        }
    }

    fn check_version(version: &str) -> Result<(), EstablishTunnelResult> {
        if  version != "HTTP/1.1" {
            debug!("Bad version {}", version);
            Err(EstablishTunnelResult::BadRequest)
        } else {
            Ok(())
        }
    }

    fn check_method(method: &str) -> Result<(), EstablishTunnelResult> {
        if method != "CONNECT" {
            debug!("Not allowed method {}", method);
            Err(EstablishTunnelResult::OperationNotAllowed)
        } else {
            Ok(())
        }
    }

    fn precondition_legal_characters(http_request: &[u8]) -> Result<(), EstablishTunnelResult> {
        for b in http_request {
            match b {
                // non-ascii characters don't make sense in this context
                32..=126 | 10 | 13 => {}
                _ => {
                    debug!("Bad request header. Illegal character: {:#04x}", b);
                    return Err(EstablishTunnelResult::BadRequest);
                }
            }
        }
        Ok(())
    }

    fn precondition_size(http_request: &[u8]) -> Result<(), EstablishTunnelResult> {
        if http_request.len() >= MAX_HTTP_REQUEST_SIZE {
            debug!(
                "Bad request header. Size {} exceeds limit {}",
                http_request.len(),
                MAX_HTTP_REQUEST_SIZE
            );
            Err(EstablishTunnelResult::BadRequest)
        } else {
            Ok(())
        }
    }

}

#[cfg(test)]
mod test2{
    use base64::decode;
    use regex::Regex;
    #[test]
    fn xor() {
        let password = b"123456";
        let hostdec = "AAMHGQQOAh0LDxsABgkLBzU=";
        let mut bytes = decode(hostdec.as_bytes()).unwrap();
        // let host = String::from_utf8_lossy(&bytes);
        let mut pasub=0;
        for i in 0..bytes.len() {
            bytes[i] ^= password[pasub as usize] | pasub;
            pasub = pasub+1;
            if pasub == password.len() as u8{
                pasub=0;
            }
        }
        println!("{}",String::from_utf8_lossy(&bytes));

        
    }

    #[test]
    fn http_obs(){
        let a = "CONNECT data.video.iqiyi.com HTTP/1.1\r\n
        Host:data.video.iqiyi.com\r\n
        Meng: CR0LGQ0ZCQkGBDU=\r\n
        User-Agent: CuteBi Linux Network, (%>w<%)\r\n
        
        ";
        let re = Regex::new(r"(: )(.+=)").unwrap();
        let caps = re.captures(a).unwrap();
        let host = caps.get(2).map_or("", |m| m.as_str());
        println!("{}",host)

    }

}


#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use regex::Regex;
    use tokio_util::codec::{Decoder, Encoder};

    use crate::http_tunnel_codec::{
        EstablishTunnelResult, HttpTunnelCodec, HttpTunnelCodecBuilder, HttpTunnelTargetBuilder,
        MAX_HTTP_REQUEST_SIZE, REQUEST_END_MARKER,
    };
    use crate::tunnel::TunnelCtxBuilder;

    #[test]
    fn test_got_http_request_partial() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Ok(None));

        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1");
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn test_got_http_request_full() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(
            result,
            Ok(Some(
                HttpTunnelTargetBuilder::default()
                    .target("foo.bar.com:443".to_string())
                    .build()
                    .unwrap(),
            ))
        );
    }

    #[test]
    fn test_got_http_request_exceeding() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        while buffer.len() <= MAX_HTTP_REQUEST_SIZE {
            buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1\r\n");
        }
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(EstablishTunnelResult::BadRequest));
    }

    #[test]
    fn test_parse_valid() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_valid_with_headers() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(
            b"CONNECT foo.bar.com:443 HTTP/1.1\r\n\
                   Host: ignored\r\n\
                   Auithorization: ignored",
        );
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_not_allowed_method() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"GET foo.bar.com:443 HTTP/1.1");
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(EstablishTunnelResult::OperationNotAllowed));
    }

    #[test]
    fn test_parse_bad_version() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.0");
        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);
        assert!(result.is_err());

        let code = result.err().unwrap();
        assert_eq!(code, EstablishTunnelResult::BadRequest);
    }

    #[test]
    fn test_parse_bad_requests() {
        let bad_requests = [
            "bad request\r\n\r\n",                       // 2 tokens
            "yet another bad request\r\n\r\n",           // 4 tokens
            "CONNECT foo.bar.cøm:443 HTTP/1.1\r\n\r\n", // non-ascii
            "CONNECT  foo.bar.com:443 HTTP/1.1\r\n\r\n", // double-space
            "CONNECT foo.bar.com:443\tHTTP/1.1\r\n\r\n", // CTL
        ];
        bad_requests.iter().for_each(|r| {
            let mut codec = build_codec();

            let mut buffer = BytesMut::new();
            buffer.put_slice(r.as_bytes());
            let result = codec.decode(&mut buffer);

            assert_eq!(
                result,
                Err(EstablishTunnelResult::BadRequest),
                "Didn't reject {}",
                r
            );
        });
    }

    #[test]
    fn test_parse_request_exceeds_size() {
        let mut codec = build_codec();
        let mut buffer = BytesMut::new();
        while !buffer.len() <= MAX_HTTP_REQUEST_SIZE {
            buffer.put_slice(b"CONNECT foo.bar.com:443 HTTP/1.1\r\n");
        }

        buffer.put_slice(REQUEST_END_MARKER);
        let result = codec.decode(&mut buffer);

        assert_eq!(result, Err(EstablishTunnelResult::BadRequest));
    }

    #[test]
    fn test_http_tunnel_encoder() {
        use crate::strum::IntoEnumIterator;

        let mut codec = build_codec();

        let pattern = Regex::new(r"^HTTP/1\.1 ([2-5][\d]{2}) [A-Z_]{2,20}\r\n\r\n").unwrap();

        for code in EstablishTunnelResult::iter() {
            let mut buffer = BytesMut::new();
            let encoded = codec.encode(code, &mut buffer);
            assert!(encoded.is_ok());

            let str = String::from_utf8(Vec::from(&buffer[..])).expect("Must be valid ASCII");

            assert!(pattern.is_match(&str), "Malformed response `{:?}`", code);
        }
    }

    fn build_codec() -> HttpTunnelCodec {
        let ctx = TunnelCtxBuilder::default().id(1).build().unwrap();

        HttpTunnelCodecBuilder::default()
            .tunnel_ctx(ctx)
            .enabled_targets(Regex::new(r"foo\.bar\.com:443").unwrap())
            .build()
            .unwrap()
    }
}
