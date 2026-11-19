use std::fmt;
use std::pin::Pin;

#[cfg(feature = "runtime-async-std")]
use async_std::io::{Read, Write, WriteExt};
use bytes::BytesMut;
use futures_util::stream::Stream;
use futures_util::task::{Context, Poll};
use futures_util::{io, ready};
use nom::Needed;
#[cfg(feature = "runtime-tokio")]
use tokio::io::{AsyncRead as Read, AsyncWrite as Write, AsyncWriteExt};

use crate::types::{Request, ResponseData};

/// Wraps a stream, and parses incoming data as imap server messages. Writes outgoing data
/// as imap client messages.
#[derive(Debug)]
pub struct ImapStream<R: Read + Write> {
    /// The underlying stream
    pub(crate) inner: R,
    /// Number of bytes the next decode operation needs if known.
    /// If the buffer contains less than this, it is a waste of time to try to parse it.
    /// If unknown, set it to 0, so decoding is always attempted.
    decode_needs: usize,
    /// The buffer.
    buffer: Buffer,

    /// True if the stream should not return any more items.
    ///
    /// This is set when reading from a stream
    /// returns an error.
    /// Afterwards the stream returns only `None`
    /// and `poll_next()` does not read
    /// from the underlying stream.
    read_closed: bool,

    /// Maximum bytes buffered for one server response.
    max_response_size: usize,

    /// Incremental structural depth checker, run before the recursive parser.
    nesting: NestingValidator,

    /// Aggregate limits and counters for the current tagged command. A
    /// response remains individually subject to `max_response_size`.
    max_command_responses: usize,
    max_command_bytes: usize,
    command_responses: usize,
    command_bytes: usize,
    command_budget_active: bool,
}

impl<R: Read + Write + Unpin> ImapStream<R> {
    pub(crate) const DEFAULT_MAX_RESPONSE_SIZE: usize = 64 * 1024 * 1024;
    pub(crate) const DEFAULT_MAX_NESTING: usize = 128;
    pub(crate) const DEFAULT_MAX_COMMAND_RESPONSES: usize = 1024;
    pub(crate) const DEFAULT_MAX_COMMAND_BYTES: usize = 128 * 1024 * 1024;

    /// Creates a new `ImapStream` based on the given `Read`er.
    pub fn new(inner: R) -> Self {
        ImapStream {
            inner,
            buffer: Buffer::new(),
            decode_needs: 0,
            read_closed: false,
            max_response_size: Self::DEFAULT_MAX_RESPONSE_SIZE,
            nesting: NestingValidator::new(Self::DEFAULT_MAX_NESTING),
            max_command_responses: Self::DEFAULT_MAX_COMMAND_RESPONSES,
            max_command_bytes: Self::DEFAULT_MAX_COMMAND_BYTES,
            command_responses: 0,
            command_bytes: 0,
            command_budget_active: false,
        }
    }

    pub async fn encode(&mut self, msg: Request) -> Result<(), io::Error> {
        // Commands routinely contain passwords, bearer tokens and mailbox
        // names.  Never put protocol payloads in logs, even at TRACE.
        log::trace!("encode: tag: {:?}, bytes: {}", msg.0, msg.1.len());

        if let Some(tag) = msg.0 {
            self.inner.write_all(tag.as_bytes()).await?;
            self.inner.write_all(b" ").await?;
        }
        self.inner.write_all(&msg.1).await?;
        self.inner.write_all(b"\r\n").await?;

        Ok(())
    }

    /// Gets a reference to the underlying stream.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Gets a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Returns underlying stream.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Flushes the underlying stream.
    pub async fn flush(&mut self) -> Result<(), io::Error> {
        self.inner.flush().await
    }

    pub fn as_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub(crate) fn set_max_response_size(&mut self, bytes: usize) -> io::Result<()> {
        if bytes == 0 || bytes < self.buffer.used() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response limit is smaller than buffered data",
            ));
        }
        self.max_response_size = bytes;
        Ok(())
    }

    pub(crate) fn set_max_nesting(&mut self, depth: usize) -> io::Result<()> {
        if depth == 0 || depth < self.nesting.depth {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nesting limit is smaller than current response depth",
            ));
        }
        self.nesting.max_depth = depth;
        Ok(())
    }

    pub(crate) fn set_command_limits(&mut self, responses: usize, bytes: usize) -> io::Result<()> {
        if responses == 0 || bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command response and byte limits must be non-zero",
            ));
        }
        self.max_command_responses = responses;
        self.max_command_bytes = bytes;
        Ok(())
    }

    /// Start accounting for a newly-written tagged command. Callers drain an
    /// abandoned prior command before invoking this, so dropping a response
    /// stream cannot reset the old command's budget.
    pub(crate) fn begin_command(&mut self) {
        self.command_responses = 0;
        self.command_bytes = 0;
        self.command_budget_active = true;
    }

    fn observe_command_response(&mut self, bytes: usize) -> io::Result<()> {
        if !self.command_budget_active {
            return Ok(());
        }
        let responses = self
            .command_responses
            .checked_add(1)
            .ok_or_else(|| io::Error::other("incoming command response count overflow"))?;
        let aggregate_bytes = self
            .command_bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("incoming command byte count overflow"))?;
        if responses > self.max_command_responses {
            return Err(io::Error::other(
                "incoming command exceeds configured response-count limit",
            ));
        }
        if aggregate_bytes > self.max_command_bytes {
            return Err(io::Error::other(
                "incoming command exceeds configured aggregate byte limit",
            ));
        }
        self.command_responses = responses;
        self.command_bytes = aggregate_bytes;
        Ok(())
    }

    /// Attempts to decode a single response from the buffer.
    ///
    /// Returns `None` if the buffer does not contain enough data.
    fn decode(&mut self) -> io::Result<Option<ResponseData>> {
        if self.buffer.used() < self.decode_needs {
            // We know that there is not enough data to decode anything
            // from previous attempts.
            return Ok(None);
        }

        let block = self.buffer.take_block();
        // Be aware, now self.buffer is invalid until block is returned or reset!

        let res = ResponseData::try_new_or_recover(block, |buf| {
            let buf = &buf[..self.buffer.used()];
            log::trace!("decode: buffered bytes: {}", buf.len());
            match imap_proto::Response::parse(buf) {
                Ok((remaining, response)) => {
                    let response_bytes = buf.len() - remaining.len();
                    if let Err(error) = self.observe_command_response(response_bytes) {
                        return Err(Some(error));
                    }
                    // TODO: figure out if we can use a minimum required size for a response.
                    self.decode_needs = 0;
                    self.buffer.reset_with_data(remaining);
                    Ok(response)
                }
                Err(nom::Err::Incomplete(Needed::Size(min))) => {
                    log::trace!("decode: incomplete data, need minimum {min} bytes");
                    let Some(needed) = self.buffer.used().checked_add(usize::from(min)) else {
                        return Err(Some(io::Error::other("incoming data too large")));
                    };
                    if needed > self.max_response_size {
                        return Err(Some(io::Error::other(
                            "incoming response exceeds configured size limit",
                        )));
                    }
                    self.decode_needs = needed;
                    Err(None)
                }
                Err(nom::Err::Incomplete(_)) => {
                    log::trace!("decode: incomplete data, need unknown number of bytes");
                    self.decode_needs = 0;
                    Err(None)
                }
                Err(other) => {
                    self.decode_needs = 0;
                    Err(Some(io::Error::other(format!("{other:?} during parsing"))))
                }
            }
        });
        match res {
            Ok(response) => {
                self.nesting.reset();
                // The bytes have already passed this check. Rebuilding the
                // incremental state is required because a parsed response may
                // leave the start of the next response in the buffer.
                self.nesting.scan(self.buffer.used_slice())?;
                Ok(Some(response))
            }
            Err((heads, err)) => {
                self.buffer.return_block(heads);
                match err {
                    Some(err) => Err(err),
                    None => Ok(None),
                }
            }
        }
    }

    fn do_poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<ResponseData>>> {
        let this = &mut *self;
        if let Some(response) = this.decode()? {
            return Poll::Ready(Some(Ok(response)));
        }
        loop {
            if this.decode_needs > this.max_response_size
                || this.buffer.used() >= this.max_response_size
            {
                return Poll::Ready(Some(Err(io::Error::other(
                    "incoming response exceeds configured size limit",
                ))));
            }
            this.buffer.ensure_capacity(this.max_response_size)?;
            let remaining_budget = this.max_response_size - this.buffer.used();
            let buf = this.buffer.free_as_mut_slice();
            let read_len = buf.len().min(remaining_budget);
            let buf = &mut buf[..read_len];

            // The buffer should have at least one byte free
            // before we try reading into it
            // so we can treat 0 bytes read as EOF.
            // This is guaranteed by `ensure_capacity()` above
            // even if it is called with 0 as an argument.
            debug_assert!(!buf.is_empty());

            #[cfg(feature = "runtime-async-std")]
            let num_bytes_read = ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;

            #[cfg(feature = "runtime-tokio")]
            let num_bytes_read = {
                let buf = &mut tokio::io::ReadBuf::new(buf);
                let start = buf.filled().len();
                ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
                buf.filled().len() - start
            };

            if num_bytes_read == 0 {
                if this.buffer.used() > 0 {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "bytes remaining in stream",
                    ))));
                }
                return Poll::Ready(None);
            }
            this.nesting.scan(&buf[..num_bytes_read])?;
            this.buffer.extend_used(num_bytes_read);
            if let Some(response) = this.decode()? {
                return Poll::Ready(Some(Ok(response)));
            }
        }
    }
}

/// Abstraction around needed buffer management.
struct Buffer {
    /// The buffer itself.
    block: BytesMut,
    /// Offset where used bytes range ends.
    offset: usize,
}

impl Buffer {
    const BLOCK_SIZE: usize = 1024 * 4;

    fn new() -> Self {
        Self {
            block: BytesMut::zeroed(Self::BLOCK_SIZE),
            offset: 0,
        }
    }

    /// Returns the number of bytes in the buffer containing data.
    fn used(&self) -> usize {
        self.offset
    }

    fn used_slice(&self) -> &[u8] {
        &self.block[..self.offset]
    }

    /// Returns the unused part of the buffer to which new data can be written.
    fn free_as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.block[self.offset..]
    }

    /// Indicate how many new bytes were written into the buffer.
    ///
    /// When new bytes are written into the slice returned by [`free_as_mut_slice`] this method
    /// should be called to extend the used portion of the buffer to include the new data.
    ///
    /// You can not write past the end of the buffer, so extending more then there is free
    /// space marks the entire buffer as used.
    ///
    /// [`free_as_mut_slice`]: Self::free_as_mut_slice
    // aka advance()?
    fn extend_used(&mut self, num_bytes: usize) {
        self.offset += num_bytes;
        if self.offset > self.block.len() {
            self.offset = self.block.len();
        }
    }

    /// Ensure the buffer has free capacity, optionally ensuring minimum buffer size.
    fn ensure_capacity(&mut self, max_capacity: usize) -> io::Result<()> {
        let free_bytes: usize = self.block.len() - self.offset;
        if free_bytes == 0 {
            self.grow(Buffer::BLOCK_SIZE, max_capacity)?;
        }

        // Assert that the buffer at least one free byte.
        debug_assert!(self.offset < self.block.len());

        Ok(())
    }

    /// Grows the buffer, ensuring there are free bytes in the tail.
    ///
    /// The specified number of bytes is only a minimum.  The buffer could grow by more as
    /// it will always grow in multiples of [`BLOCK_SIZE`].
    ///
    /// If the size would be larger than [`MAX_CAPACITY`] an error is returned.
    ///
    /// [`BLOCK_SIZE`]: Self::BLOCK_SIZE
    /// [`MAX_CAPACITY`]: Self::MAX_CAPACITY
    fn grow(&mut self, num_bytes: usize, max_capacity: usize) -> io::Result<()> {
        let min_size = self.block.len() + num_bytes;
        let rounded_size = match min_size % Self::BLOCK_SIZE {
            0 => min_size,
            n => min_size + (Self::BLOCK_SIZE - n),
        };
        let new_size = rounded_size.min(max_capacity);
        if new_size <= self.block.len() {
            Err(io::Error::other("incoming data too large"))
        } else {
            self.block.resize(new_size, 0);
            Ok(())
        }
    }

    /// Return the block backing the buffer.
    ///
    /// Next you *must* either return this block using [`return_block`] or call
    /// [`reset_with_data`].
    ///
    /// [`return_block`]: Self::return_block
    /// [`reset_with_data`]: Self::reset_with_data
    // TODO: Enforce this with typestate.
    fn take_block(&mut self) -> BytesMut {
        std::mem::replace(&mut self.block, BytesMut::zeroed(Self::BLOCK_SIZE))
    }

    /// Reset the buffer to be a new allocation with given data copied in.
    ///
    /// This allows the previously returned block from `get_block` to be used in and owned
    /// by the [ResponseData].
    ///
    /// This does not do any bounds checking to see if the new buffer would exceed the
    /// maximum size.  It will however ensure that there is at least some free space at the
    /// end of the buffer so that the next reading operation won't need to realloc right
    /// away.  This could be wasteful if the next action on the buffer is another decode
    /// rather than a read, but we don't know.
    fn reset_with_data(&mut self, data: &[u8]) {
        let min_size = data.len();
        let new_size = match min_size % Self::BLOCK_SIZE {
            0 => min_size + Self::BLOCK_SIZE,
            n => min_size + (Self::BLOCK_SIZE - n),
        };
        self.block = BytesMut::zeroed(new_size);
        self.block[..data.len()].copy_from_slice(data);

        self.offset = data.len();
    }

    /// Return the block which backs this buffer.
    fn return_block(&mut self, block: BytesMut) {
        self.block = block;
    }
}

#[derive(Debug)]
struct NestingValidator {
    depth: usize,
    max_depth: usize,
    state: ScanState,
}

#[derive(Debug)]
enum ScanState {
    Normal,
    Quoted { escaped: bool },
    LiteralLength { value: usize, saw_digit: bool },
    LiteralCr { value: usize },
    LiteralLf { value: usize },
    LiteralData { remaining: usize },
}

impl NestingValidator {
    fn new(max_depth: usize) -> Self {
        Self {
            depth: 0,
            max_depth,
            state: ScanState::Normal,
        }
    }

    fn reset(&mut self) {
        self.depth = 0;
        self.state = ScanState::Normal;
    }

    fn scan(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut index = 0;
        while index < bytes.len() {
            if let ScanState::LiteralData { remaining: 0 } = self.state {
                self.state = ScanState::Normal;
                continue;
            }

            let byte = bytes[index];
            let mut consume = true;
            match &mut self.state {
                ScanState::Normal => match byte {
                    b'"' => self.state = ScanState::Quoted { escaped: false },
                    b'(' => {
                        self.depth += 1;
                        if self.depth > self.max_depth {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "incoming response exceeds configured nesting limit",
                            ));
                        }
                    }
                    b')' => self.depth = self.depth.saturating_sub(1),
                    b'{' => {
                        self.state = ScanState::LiteralLength {
                            value: 0,
                            saw_digit: false,
                        }
                    }
                    _ => {}
                },
                ScanState::Quoted { escaped } => {
                    if *escaped {
                        *escaped = false;
                    } else if byte == b'\\' {
                        *escaped = true;
                    } else if byte == b'"' {
                        self.state = ScanState::Normal;
                    }
                }
                ScanState::LiteralLength { value, saw_digit } => match byte {
                    b'0'..=b'9' => {
                        *saw_digit = true;
                        *value = value
                            .checked_mul(10)
                            .and_then(|n| n.checked_add(usize::from(byte - b'0')))
                            .ok_or_else(|| io::Error::other("literal length overflow"))?;
                    }
                    b'+' => {}
                    b'}' if *saw_digit => {
                        self.state = ScanState::LiteralCr { value: *value };
                    }
                    _ => {
                        self.state = ScanState::Normal;
                        consume = false;
                    }
                },
                ScanState::LiteralCr { value } => {
                    if byte == b'\r' {
                        self.state = ScanState::LiteralLf { value: *value };
                    } else {
                        self.state = ScanState::Normal;
                        consume = false;
                    }
                }
                ScanState::LiteralLf { value } => {
                    if byte == b'\n' {
                        self.state = ScanState::LiteralData { remaining: *value };
                    } else {
                        self.state = ScanState::Normal;
                        consume = false;
                    }
                }
                ScanState::LiteralData { remaining } => *remaining -= 1,
            }
            if consume {
                index += 1;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("used", &self.used())
            .field("capacity", &self.block.capacity())
            .finish()
    }
}

impl<R: Read + Write + Unpin> Stream for ImapStream<R> {
    type Item = io::Result<ResponseData>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.read_closed {
            return Poll::Ready(None);
        }
        let res = match ready!(self.as_mut().do_poll_next(cx)) {
            None => None,
            Some(Err(err)) => {
                self.read_closed = true;
                Some(Err(err))
            }
            Some(Ok(item)) => Some(Ok(item)),
        };
        Poll::Ready(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pin_project::pin_project;
    use std::io::Write as _;

    /// Wrapper for a stream that
    /// fails once on a first read.
    ///
    /// Writes are discarded.
    #[pin_project]
    struct FailingStream {
        #[pin]
        inner: &'static [u8],
        has_failed: bool,
    }

    impl FailingStream {
        fn new(buf: &'static [u8]) -> Self {
            Self {
                inner: buf,
                has_failed: false,
            }
        }
    }

    #[cfg(feature = "runtime-tokio")]
    impl Read for FailingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let this = self.project();
            if !*this.has_failed {
                *this.has_failed = true;

                Poll::Ready(Err(std::io::Error::other("Failure")))
            } else {
                this.inner.poll_read(cx, buf)
            }
        }
    }

    #[cfg(feature = "runtime-async-std")]
    impl Read for FailingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<async_std::io::Result<usize>> {
            let this = self.project();
            if !*this.has_failed {
                *this.has_failed = true;

                Poll::Ready(Err(std::io::Error::other("Failure")))
            } else {
                this.inner.poll_read(cx, buf)
            }
        }
    }

    #[cfg(feature = "runtime-tokio")]
    impl Write for FailingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<tokio::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[cfg(feature = "runtime-async-std")]
    impl Write for FailingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<async_std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<async_std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<async_std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Tests that stream returns `None` after
    /// a single error of the underlying stream.
    ///
    /// This is need to prevent accidental
    /// reading from a network stream
    /// after a temporary error such as a timeout
    /// or returning an inifinite stream of errors.
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn test_imap_stream_error() {
        use futures_util::StreamExt;

        let mock_stream = FailingStream::new(b"* OK\r\n");
        let mut imap_stream = ImapStream::new(mock_stream);

        // First call is an error because underlying stream fails.
        assert!(imap_stream.next().await.unwrap().is_err());

        // IMAP stream should end even though underlying stream fails only once.
        assert!(imap_stream.next().await.is_none());
    }

    #[test]
    fn test_buffer_empty() {
        let buf = Buffer::new();
        assert_eq!(buf.used(), 0);

        let mut buf = Buffer::new();
        let slice: &[u8] = buf.free_as_mut_slice();
        assert_eq!(slice.len(), Buffer::BLOCK_SIZE);
        assert_eq!(slice.len(), buf.block.len());
    }

    #[test]
    fn test_buffer_extend_use() {
        let mut buf = Buffer::new();
        buf.extend_used(3);
        assert_eq!(buf.used(), 3);
        let slice = buf.free_as_mut_slice();
        assert_eq!(slice.len(), Buffer::BLOCK_SIZE - 3);

        // Extend past the end of the buffer.
        buf.extend_used(Buffer::BLOCK_SIZE);
        assert_eq!(buf.used(), Buffer::BLOCK_SIZE);
        assert_eq!(buf.offset, Buffer::BLOCK_SIZE);
        assert_eq!(buf.block.len(), buf.offset);
        let slice = buf.free_as_mut_slice();
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn test_buffer_write_read() {
        let mut buf = Buffer::new();
        let mut slice = buf.free_as_mut_slice();
        slice.write_all(b"hello").unwrap();
        buf.extend_used(b"hello".len());

        let slice = &buf.block[..buf.used()];
        assert_eq!(slice, b"hello");
        assert_eq!(buf.free_as_mut_slice().len(), buf.block.len() - buf.offset);
    }

    #[test]
    fn test_buffer_grow() {
        let mut buf = Buffer::new();
        assert_eq!(buf.block.len(), Buffer::BLOCK_SIZE);
        buf.grow(1, 4 * Buffer::BLOCK_SIZE).unwrap();
        assert_eq!(buf.block.len(), 2 * Buffer::BLOCK_SIZE);

        buf.grow(Buffer::BLOCK_SIZE + 1, 4 * Buffer::BLOCK_SIZE)
            .unwrap();
        assert_eq!(buf.block.len(), 4 * Buffer::BLOCK_SIZE);

        let ret = buf.grow(1, 4 * Buffer::BLOCK_SIZE);
        assert!(ret.is_err());
    }

    #[test]
    fn test_buffer_ensure_capacity() {
        // Initial state: 1 byte capacity left, initial size.
        let mut buf = Buffer::new();
        buf.extend_used(Buffer::BLOCK_SIZE - 1);
        assert_eq!(buf.free_as_mut_slice().len(), 1);
        assert_eq!(buf.block.len(), Buffer::BLOCK_SIZE);

        // Still has capacity.
        buf.ensure_capacity(3 * Buffer::BLOCK_SIZE).unwrap();
        assert_eq!(buf.free_as_mut_slice().len(), 1);
        assert_eq!(buf.block.len(), Buffer::BLOCK_SIZE);

        // No more capacity, initial size.
        buf.extend_used(1);
        assert_eq!(buf.free_as_mut_slice().len(), 0);
        assert_eq!(buf.block.len(), Buffer::BLOCK_SIZE);

        // No capacity: grow by one block, rather than to an advertised literal.
        buf.ensure_capacity(3 * Buffer::BLOCK_SIZE).unwrap();
        assert_eq!(buf.free_as_mut_slice().len(), Buffer::BLOCK_SIZE);
        assert_eq!(buf.block.len(), 2 * Buffer::BLOCK_SIZE);

        // Existing free capacity does not trigger speculative allocation.
        buf.extend_used(5);
        assert_eq!(buf.offset, Buffer::BLOCK_SIZE + 5);
        buf.ensure_capacity(3 * Buffer::BLOCK_SIZE).unwrap();
        assert_eq!(buf.free_as_mut_slice().len(), Buffer::BLOCK_SIZE - 5);
        assert_eq!(buf.block.len(), 2 * Buffer::BLOCK_SIZE);
    }

    /// Regression test for a bug in ensure_capacity() caused
    /// by a bug in byte-pool crate 0.2.2 dependency.
    ///
    /// ensure_capacity() sometimes did not ensure that
    /// at least one byte is available, which in turn
    /// resulted in attempt to read into a buffer of zero size.
    /// When poll_read() reads into a buffer of zero size,
    /// it can only read zero bytes, which is indistinguishable
    /// from EOF and resulted in an erroneous detection of EOF
    /// when in fact the stream was not closed.
    #[test]
    fn test_ensure_capacity_loop() {
        let mut buf = Buffer::new();

        for _ in 1..500 {
            buf.ensure_capacity(500 * Buffer::BLOCK_SIZE).unwrap();

            // Test that we can read at least 1 byte.
            let free = buf.free_as_mut_slice();
            let used = free.len();
            assert!(used > 0);

            // Use as much as allowed.
            buf.extend_used(used);

            // Return the allocation and continue growing one block at a time.
            let block = buf.take_block();
            assert!(block.len() >= Buffer::BLOCK_SIZE);
            buf.return_block(block);
        }
    }

    #[test]
    fn test_buffer_take_and_return_block() {
        // This test identifies blocks by their size.
        let mut buf = Buffer::new();
        buf.grow(1, 2 * Buffer::BLOCK_SIZE).unwrap();
        let block_size = buf.block.len();

        let block = buf.take_block();
        assert_eq!(block.len(), block_size);
        assert_ne!(buf.block.len(), block_size);

        buf.return_block(block);
        assert_eq!(buf.block.len(), block_size);
    }

    #[test]
    fn test_buffer_reset_with_data() {
        // This test identifies blocks by their size.
        let data: [u8; 2 * Buffer::BLOCK_SIZE] = [b'a'; 2 * Buffer::BLOCK_SIZE];
        let mut buf = Buffer::new();
        let block_size = buf.block.len();
        assert_eq!(block_size, Buffer::BLOCK_SIZE);
        buf.reset_with_data(&data);
        assert_ne!(buf.block.len(), block_size);
        assert_eq!(buf.block.len(), 3 * Buffer::BLOCK_SIZE);
        assert!(!buf.free_as_mut_slice().is_empty());

        let data: [u8; 0] = [];
        let mut buf = Buffer::new();
        buf.reset_with_data(&data);
        assert_eq!(buf.block.len(), Buffer::BLOCK_SIZE);
    }

    #[test]
    fn test_buffer_debug() {
        assert_eq!(
            format!("{:?}", Buffer::new()),
            format!(r#"Buffer {{ used: 0, capacity: {} }}"#, Buffer::BLOCK_SIZE)
        );
    }
}
