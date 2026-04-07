#pragma once

#include <algorithm>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <vector>

namespace fastcrypto {

/**
 * Lightweight thread pool for offloading async crypto operations.
 * Initialized once on module load with bounded concurrency.
 */
class ThreadPool {
public:
  explicit ThreadPool(
      size_t numThreads = std::min(
          static_cast<size_t>(8),
          std::max(static_cast<size_t>(2),
                   static_cast<size_t>(std::thread::hardware_concurrency()))))
      : stop_(false) {
    for (size_t i = 0; i < numThreads; ++i) {
      workers_.emplace_back([this] { workerLoop(); });
    }
  }

  ~ThreadPool() {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      stop_ = true;
    }
    condition_.notify_all();
    for (auto &worker : workers_) {
      if (worker.joinable()) {
        worker.join();
      }
    }
  }

  // Non-copyable, non-movable
  ThreadPool(const ThreadPool &) = delete;
  ThreadPool &operator=(const ThreadPool &) = delete;

  template <class F, class... Args>
  auto enqueue(F &&f, Args &&...args)
      -> std::future<typename std::invoke_result<F, Args...>::type> {
    using ReturnType = typename std::invoke_result<F, Args...>::type;

    auto task = std::make_shared<std::packaged_task<ReturnType()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<ReturnType> result = task->get_future();
    {
      std::unique_lock<std::mutex> lock(mutex_);
      if (stop_) {
        throw std::runtime_error("enqueue on stopped ThreadPool");
      }
      tasks_.emplace([task]() { (*task)(); });
    }
    condition_.notify_one();
    return result;
  }

  size_t threadCount() const { return workers_.size(); }

private:
  void workerLoop() {
    while (true) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
        if (stop_ && tasks_.empty()) {
          return;
        }
        task = std::move(tasks_.front());
        tasks_.pop();
      }
      task();
    }
  }

  std::vector<std::thread> workers_;
  std::queue<std::function<void()>> tasks_;
  std::mutex mutex_;
  std::condition_variable condition_;
  bool stop_;
};

} // namespace fastcrypto
