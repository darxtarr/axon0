/// Hybrid Logical Clock implementation per Kulkarni et al.
///
/// Combines Lamport logical clocks with physical time to provide:
/// - Causal ordering (happens-before relationships)
/// - Bounded divergence from physical time
/// - Monotonicity even with clock drift
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hlc {
    pub physical_ms: u64,
    pub logical: u32,
}

impl Hlc {
    /// Create a new HLC with initial physical time
    pub fn new(initial_ms: u64) -> Self {
        Self {
            physical_ms: initial_ms,
            logical: 0,
        }
    }

    /// Update HLC on local event (sending a message, local state change, etc.)
    ///
    /// Rules:
    /// - pt = now_ms (current physical time)
    /// - pt' = max(pt, self.physical_ms)
    /// - if pt' == self.physical_ms → logical += 1
    /// - else → logical = 0
    /// - physical_ms = pt'
    pub fn tick_local(&mut self, now_ms: u64) {
        let pt = now_ms;
        let pt_prime = pt.max(self.physical_ms);

        if pt_prime == self.physical_ms {
            self.logical += 1;
        } else {
            self.logical = 0;
        }

        self.physical_ms = pt_prime;
    }

    /// Update HLC on receive event (receiving a message with remote HLC)
    ///
    /// Rules:
    /// - pt = now_ms (current physical time)
    /// - pt' = max(pt, self.physical_ms, remote.physical_ms)
    /// - Update logical counter based on which timestamp(s) match pt':
    ///   - If pt' == self.physical_ms && pt' == remote.physical_ms:
    ///       logical = max(self.logical, remote.logical) + 1
    ///   - Else if pt' == self.physical_ms:
    ///       logical = self.logical + 1
    ///   - Else if pt' == remote.physical_ms:
    ///       logical = remote.logical + 1
    ///   - Else:
    ///       logical = 0
    /// - physical_ms = pt'
    pub fn tick_receive(&mut self, now_ms: u64, remote: Hlc) {
        let pt = now_ms;
        let pt_prime = pt.max(self.physical_ms).max(remote.physical_ms);

        self.logical = if pt_prime == self.physical_ms && pt_prime == remote.physical_ms {
            self.logical.max(remote.logical) + 1
        } else if pt_prime == self.physical_ms {
            self.logical + 1
        } else if pt_prime == remote.physical_ms {
            remote.logical + 1
        } else {
            0
        };

        self.physical_ms = pt_prime;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_local_monotonic() {
        let mut hlc = Hlc::new(1000);

        // Tick at same physical time
        hlc.tick_local(1000);
        assert_eq!(hlc.physical_ms, 1000);
        assert_eq!(hlc.logical, 1);

        hlc.tick_local(1000);
        assert_eq!(hlc.physical_ms, 1000);
        assert_eq!(hlc.logical, 2);

        // Physical time advances
        hlc.tick_local(1005);
        assert_eq!(hlc.physical_ms, 1005);
        assert_eq!(hlc.logical, 0);

        // Physical time goes backward (clock drift)
        hlc.tick_local(1003);
        assert_eq!(hlc.physical_ms, 1005); // physical doesn't go backward
        assert_eq!(hlc.logical, 1); // logical increments
    }

    #[test]
    fn hlc_receive_remote_behind() {
        let mut hlc = Hlc::new(1000);
        hlc.tick_local(1000); // (1000, 1)

        let remote = Hlc {
            physical_ms: 900,
            logical: 5,
        };

        hlc.tick_receive(950, remote);

        // pt' = max(950, 1000, 900) = 1000
        // pt' == self.physical_ms (1000)
        // → logical = self.logical + 1 = 2
        assert_eq!(hlc.physical_ms, 1000);
        assert_eq!(hlc.logical, 2);
    }

    #[test]
    fn hlc_receive_remote_ahead() {
        let mut hlc = Hlc::new(1000);
        hlc.tick_local(1000); // (1000, 1)

        let remote = Hlc {
            physical_ms: 1200,
            logical: 3,
        };

        hlc.tick_receive(1100, remote);

        // pt' = max(1100, 1000, 1200) = 1200
        // pt' == remote.physical_ms
        // → logical = remote.logical + 1 = 4
        assert_eq!(hlc.physical_ms, 1200);
        assert_eq!(hlc.logical, 4);
    }

    #[test]
    fn hlc_receive_remote_equal() {
        let mut hlc = Hlc::new(1000);
        hlc.tick_local(1000); // (1000, 1)

        let remote = Hlc {
            physical_ms: 1000,
            logical: 5,
        };

        hlc.tick_receive(1000, remote);

        // pt' = max(1000, 1000, 1000) = 1000
        // pt' == self.physical_ms && pt' == remote.physical_ms
        // → logical = max(1, 5) + 1 = 6
        assert_eq!(hlc.physical_ms, 1000);
        assert_eq!(hlc.logical, 6);
    }

    #[test]
    fn hlc_receive_all_different() {
        let mut hlc = Hlc::new(1000);
        hlc.tick_local(1050); // (1050, 0)

        let remote = Hlc {
            physical_ms: 1030,
            logical: 7,
        };

        hlc.tick_receive(1100, remote);

        // pt' = max(1100, 1050, 1030) = 1100
        // pt' != self.physical_ms && pt' != remote.physical_ms
        // → logical = 0
        assert_eq!(hlc.physical_ms, 1100);
        assert_eq!(hlc.logical, 0);
    }

    #[test]
    fn hlc_ordering() {
        let hlc1 = Hlc {
            physical_ms: 1000,
            logical: 5,
        };
        let hlc2 = Hlc {
            physical_ms: 1000,
            logical: 10,
        };
        let hlc3 = Hlc {
            physical_ms: 1001,
            logical: 0,
        };

        assert!(hlc1 < hlc2); // same physical, logical matters
        assert!(hlc2 < hlc3); // physical time dominates
    }
}
