use tokio::time::{timeout, Duration};

// Client
enum State {
    Preparing,
    Sending,
    Waiting,
    Finished,
}

enum Event {
    BufferNextFlight,
    SendFlight,
    SetRetransmissionTimer,
    TimerExpires,
    ReadRetransmit,
    SendHelloRequest,
    RecvHelloRequestSendClientHello,
    ReceiveNextFlight,
    ReceiveLastFlight,
}

struct Machine {
    timeout: Duration,
    state: State,
    // TODO, eventually, the machine will hold epoch, sequence number, message sequence, etc, keeping state out of DTLS and Handshake messages.
    // It will instead pass changes to new Machine objects, that will pass them to new DTLS/Handshake objects
}

// TODO how to implement this so that it either eventually succeeds or times out and we know which?
async fn long_future() {
    // do work here
}

impl Default for Machine {
    fn default() -> Self {
        Self{timeout: Duration::from_secs(1), state: State::Preparing} // Initial: 1 second, double every retransmission until 60s
    }
}

impl Machine {
    fn new() -> Self {
        Self::default()
    }
    fn next(self, event: Event) -> Self {
        match(self, event) {
            (State::Preparing, Event::BufferNextFlight) => Self {state: State::Sending}
            (State::Waiting, )
            (State::Finished, )
            (_, _) => Self {timeout: self.timeout * 2, state: State::Preparing}
        }
    }
    fn run(self) /*-> Event*/ {
        let res = timeout(self.timeout, long_future);
        match self.state {
            State::Preparing => {
                // Buffer flight. Noop for now until we handle fragmentation
                //Event::BufferNextFlight and go into SENDING state
            },
            State::Sending => {
                // Send buffered flight
                // If this is the last flight, enter FINISHED
                // Else, set a retransmit timer and enter waiting
            }
            State::Waiting => {
                // 1. If timer expires, go to SENDING and re-send the last flight
                // 2. Reads a re-transmitted flight from peer. goto SENDING
                // 3. Recvs next flight of messages. If final flight, goto FINISHED. If need to send new flight, goto PREPARING.
            }
            State::Finished => {
                // Can now send Application data
            }
            //_ => { println!("Default of sorts. TimerExpires so we move on to the next state"); Event::TimerExpires }
        }
    }
}

// Inspiration
// https://play.rust-lang.org/?gist=ee3e4df093c136ced7b394dc7ffb78e1&version=stable&backtrace=0
// https://hoverbear.org/blog/rust-state-machine-pattern/#generically-sophistication
// https://github.com/Munksgaard/session-types (but not many downloads, don't use directly)
// https://blog.yoshuawuyts.com/state-machines/
//
// I guess client will loop: establish a UDP conn, get input over DTLS by going through state.
// Need to send about Client API. Is it just Send/Recv?
//