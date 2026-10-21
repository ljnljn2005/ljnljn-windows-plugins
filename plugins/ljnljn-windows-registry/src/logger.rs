//! 纯解析层的最小诊断通道。
//!
//! 测试环境把消息收集到线程局部缓冲区,供断言使用;没有安装 sink 时消息丢弃。
//! 生产路径默认不依赖任何全局状态(宿主仍会通过它的日志展示摘要与限制)。

use std::cell::RefCell;

thread_local! {
    static BUFFER: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// 开启当前线程的诊断收集,返回之前的缓冲(用于测试嵌套)。
pub fn begin_capture() -> Option<Vec<String>> {
    BUFFER.with(|buffer| buffer.replace(Some(Vec::new())))
}

/// 结束收集并取回消息。
pub fn end_capture() -> Vec<String> {
    BUFFER.with(|buffer| buffer.replace(None)).unwrap_or_default()
}

pub fn warn(message: &str) {
    BUFFER.with(|buffer| {
        if let Some(messages) = buffer.borrow_mut().as_mut() {
            messages.push(message.to_string());
        }
    });
}
