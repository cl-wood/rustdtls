use crate::errors::DTLSError;

pub trait Transport {
    fn send(&self, buf: &[u8]) -> Result<(), DTLSError>;
    fn recv(&self, buf: &mut [u8]) -> Result<usize, DTLSError>;

    fn datagram_max(&self) -> usize;
    fn current_pmtu_estimate(&self) -> Option<usize>;
    // TODO don't overrun likely congestion window for DCCP, etc
    // possible api (Config, Session, Send, Recv, Max Size, PMTU, etc),
}
