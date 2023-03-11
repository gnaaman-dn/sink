use std::{pin::Pin, task::Poll};

use bytes::Bytes;
use reqwest::Response;
use tokio::io::{AsyncBufRead, AsyncRead};

pub struct ResponseAsyncReader {
    response: Pin<Box<dyn Send + futures_core::Stream<Item = reqwest::Result<Bytes>>>>,
    chunk: Option<(Bytes, usize)>,
}

impl ResponseAsyncReader {
    pub fn new(response: Response) -> Self {
        Self {
            response: Box::pin(response.bytes_stream()),
            chunk: None,
        }
    }

    fn poll_chunk(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<Bytes>> {
        let self_ = self.get_mut();
        match self_.response.as_mut().poll_next(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(Bytes::from_static(&[]))),
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Ready(Some(Ok(b))) => std::task::Poll::Ready(Ok(b)),
        }
    }
}

impl AsyncRead for ResponseAsyncReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let f = self.as_mut().poll_fill_buf(cx)?;

        if let Poll::Ready(buf_ref) = f {
            let bytes_to_copy = buf.remaining().min(buf_ref.len());
            buf.put_slice(&buf_ref[..bytes_to_copy]);
            self.consume(bytes_to_copy);
        }
        todo!()
    }
}

impl AsyncBufRead for ResponseAsyncReader {
    fn poll_fill_buf(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        let mut self_ = self.as_mut();
        if self_.chunk.is_none() {
            if let Poll::Ready(chunk) = self_.as_mut().poll_chunk(cx)? {
                self_.chunk = Some((chunk, 0));
            }
        }

        if let Some((chunk, start)) = &self.get_mut().chunk {
            Poll::Ready(Ok(&chunk[*start..]))
        } else {
            Poll::Pending
        }
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let mut self_ = self.as_mut();
        self_.chunk = match self_.chunk.take() {
            None => None,
            Some((chunk, mut start)) => {
                start += amt;
                if start >= chunk.len() {
                    None
                } else {
                    Some((chunk, start))
                }
            }
        }
    }
}
