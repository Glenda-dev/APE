use alloc::collections::VecDeque;

use super::SharedPagePoolPolicy;

/// LRU（Least Recently Used）示例策略。
#[derive(Debug, Default)]
pub struct LruPolicy {
    order: VecDeque<usize>,
}

impl LruPolicy {
    pub fn new() -> Self {
        Self { order: VecDeque::new() }
    }

    fn make_mru(&mut self, slot: usize) {
        if let Some(pos) = self.order.iter().position(|&x| x == slot) {
            self.order.remove(pos);
        }
        self.order.push_back(slot);
    }
}

impl SharedPagePoolPolicy for LruPolicy {
    fn touch(&mut self, slot: usize) {
        self.make_mru(slot);
    }

    fn insert(&mut self, slot: usize) {
        self.make_mru(slot);
    }

    fn remove(&mut self, slot: usize) {
        if let Some(pos) = self.order.iter().position(|&x| x == slot) {
            self.order.remove(pos);
        }
    }

    fn victim(&mut self, occupied: &[bool]) -> Option<usize> {
        while let Some(&slot) = self.order.front() {
            if occupied.get(slot).copied().unwrap_or(false) {
                return Some(slot);
            }
            self.order.pop_front();
        }

        occupied.iter().position(|used| *used)
    }
}
