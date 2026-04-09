pub mod lru;

/// 共享内存页池替换策略接口。
///
/// 通过该接口，页池可替换为 LRU/FIFO/Clock 等不同策略。
pub trait SharedPagePoolPolicy {
    /// 记录一个槽位被访问（命中）。
    fn touch(&mut self, slot: usize);

    /// 记录一个槽位被新插入。
    fn insert(&mut self, slot: usize);

    /// 记录一个槽位被移除。
    fn remove(&mut self, slot: usize);

    /// 从当前已占用槽位中选择一个牺牲者。
    fn victim(&mut self, occupied: &[bool]) -> Option<usize>;
}
