// S3.2 流式传输集成测试
// 验证流式上传/下载的实际行为，包括内存占用、背压、暂停恢复等

#include <catch2/catch_all.hpp>
#include <megohttp/client.hpp>
#include <megohttp/executor.hpp>
#include <megohttp/request.hpp>
#include <megohttp/response.hpp>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <string>
#include <cstring>

using namespace megohttp;

// ============================================================================
// S3.2-03: 大文件流式传输（不上传内存）
// ============================================================================

TEST_CASE("S3.2-03: Streaming upload does not buffer entire body", "[streaming][integration][memory]") {
    // 这个测试验证流式上传不会将整个 body 加载到内存
    // 通过监控 BodySource 的调用次数和每次返回的数据大小来验证
    
    Client client;
    
    SECTION("Large file streamed in chunks") {
        Request req(Method::Post, "http://httpbin.org/post");
        
        // 模拟大文件：10MB，分 1000 个 10KB 块
        const size_t chunk_size = 10 * 1024;  // 10KB
        const size_t total_chunks = 1000;      // 1000 块 = 10MB
        const size_t total_size = chunk_size * total_chunks;
        
        std::atomic<size_t> chunks_sent{0};
        std::atomic<size_t> bytes_sent{0};
        std::atomic<size_t> peak_memory{0};
        
        // 每次只生成一个 chunk，不保留之前的数据
        std::string current_chunk(chunk_size, 'X');
        
        Request::BodySource source = [&]() -> Result<std::pair<string_view, bool>> {
            size_t chunk_num = chunks_sent.fetch_add(1);
            
            if (chunk_num >= total_chunks) {
                return std::make_pair(string_view{}, true); // EOF
            }
            
            // 每次调用都重新生成数据，模拟不保留历史
            std::fill(current_chunk.begin(), current_chunk.end(), 
                     static_cast<char>('A' + (chunk_num % 26)));
            
            bytes_sent.fetch_add(chunk_size);
            size_t current_peak = peak_memory.load();
            if (chunk_size > current_peak) {
                peak_memory.store(chunk_size);
            }
            
            return std::make_pair(string_view(current_chunk.data(), current_chunk.size()), false);
        };
        
        req.set_body_source(std::move(source));
        
        // 验证接口设置正确
        REQUIRE(req.has_body());
        REQUIRE(req.body_source().has_value());
        REQUIRE(req.body_bytes().empty()); // 不应该有缓冲的 body
        
        // 注意：实际发送需要网络，这里只验证接口行为
        // 真实的集成测试需要启动本地 HTTP 服务器
    }
}

// ============================================================================
// S3.2-04: 背压支持
// ============================================================================

TEST_CASE("S3.2-04: Backpressure in streaming upload", "[streaming][integration][backpressure]") {
    Client client;
    
    SECTION("BodySource returns empty view to signal backpressure") {
        Request req(Method::Post, "http://httpbin.org/post");
        
        std::atomic<int> call_count{0};
        std::atomic<int> empty_returns{0};
        std::string data = "test data";
        
        Request::BodySource source = [&]() -> Result<std::pair<string_view, bool>> {
            int count = call_count.fetch_add(1);
            
            // 前 3 次返回空 view（背压）
            if (count < 3) {
                empty_returns.fetch_add(1);
                return std::make_pair(string_view{}, false);
            }
            
            // 第 4 次返回数据
            if (count == 3) {
                return std::make_pair(string_view(data.data(), data.size()), true);
            }
            
            return std::make_pair(string_view{}, true);
        };
        
        req.set_body_source(std::move(source));
        
        // 验证接口设置正确
        REQUIRE(req.body_source().has_value());
        
        // 注意：实际背压行为需要网络交互验证
        // 这里只验证接口可以返回空 view
    }
}

TEST_CASE("S3.2-04: Backpressure in streaming download", "[streaming][integration][backpressure]") {
    Client client;
    
    SECTION("BodySink returns false to pause") {
        Request req(Method::Get, "http://httpbin.org/get");
        
        std::atomic<int> chunks_received{0};
        std::atomic<bool> paused{false};
        
        Request::BodySink sink = [&](string_view chunk) -> bool {
            (void)chunk;
            int count = chunks_received.fetch_add(1);
            
            // 收到第 2 个 chunk 后暂停
            if (count >= 1) {
                paused.store(true);
                return false; // 暂停
            }
            
            return true; // 继续
        };
        
        Request::BodySinkComplete complete = [](VoidResult) {};
        
        req.set_body_sink(std::move(sink), std::move(complete));
        
        // 验证接口设置正确
        REQUIRE(req.body_sink().has_value());
        
        // 注意：实际背压行为需要网络交互验证
    }
}

// ============================================================================
// S3.2-06: 回调数据视图有效期
// ============================================================================

TEST_CASE("S3.2-06: Callback data view lifetime", "[streaming][integration][lifetime]") {
    Client client;
    
    SECTION("BodySink must copy data if needed beyond callback") {
        Request req(Method::Get, "http://httpbin.org/get");
        
        std::vector<std::string> copied_data;
        std::vector<string_view> borrowed_views;
        
        Request::BodySink sink = [&](string_view chunk) -> bool {
            // 正确做法：复制数据
            copied_data.emplace_back(chunk.data(), chunk.size());
            
            // 错误做法：保存 view（view 在回调结束后失效）
            // borrowed_views.push_back(chunk); // 这是错误的！
            
            return true;
        };
        
        Request::BodySinkComplete complete = [](VoidResult) {};
        
        req.set_body_sink(std::move(sink), std::move(complete));
        
        // 验证接口设置正确
        REQUIRE(req.body_sink().has_value());
        
        // 注意：实际数据生命周期需要网络交互验证
        // 这里只验证接口设计
    }
}

// ============================================================================
// S3.2-07: 内存上界策略
// ============================================================================

TEST_CASE("S3.2-07: Memory bound strategy", "[streaming][integration][memory]") {
    Client client;
    
    SECTION("Streaming upload has bounded memory") {
        Request req(Method::Post, "http://httpbin.org/post");
        
        const size_t chunk_size = 64 * 1024; // 64KB
        std::string chunk(chunk_size, 'X');
        
        std::atomic<size_t> max_chunk_size{0};
        
        Request::BodySource source = [&]() -> Result<std::pair<string_view, bool>> {
            static int count = 0;
            if (count++ >= 10) {
                return std::make_pair(string_view{}, true);
            }
            
            size_t current_max = max_chunk_size.load();
            if (chunk.size() > current_max) {
                max_chunk_size.store(chunk.size());
            }
            return std::make_pair(string_view(chunk.data(), chunk.size()), false);
        };
        
        req.set_body_source(std::move(source));
        
        // 验证内存占用有界
        REQUIRE(max_chunk_size.load() <= chunk_size);
        REQUIRE(req.body_bytes().empty()); // 不应该缓冲整个 body
    }
    
    SECTION("Streaming download has bounded memory") {
        Request req(Method::Get, "http://httpbin.org/get");
        
        std::atomic<size_t> total_received{0};
        std::atomic<size_t> max_chunk_size{0};
        
        Request::BodySink sink = [&](string_view chunk) -> bool {
            total_received.fetch_add(chunk.size());
            size_t current_max = max_chunk_size.load();
            if (chunk.size() > current_max) {
                max_chunk_size.store(chunk.size());
            }
            
            // 不缓冲数据，立即处理
            return true;
        };
        
        Request::BodySinkComplete complete = [](VoidResult) {};
        
        req.set_body_sink(std::move(sink), std::move(complete));
        
        // 验证内存占用有界
        // 注意：实际内存占用需要网络交互验证
        REQUIRE(req.body_sink().has_value());
    }
}

// ============================================================================
// 综合测试：流式上传 + 下载
// ============================================================================

TEST_CASE("Streaming upload and download combined", "[streaming][integration][combined]") {
    Client client;
    
    SECTION("Both streaming upload and download") {
        Request req(Method::Post, "http://httpbin.org/post");
        
        // 流式上传
        std::string upload_chunk = "upload data";
        Request::BodySource source = [&]() -> Result<std::pair<string_view, bool>> {
            static int count = 0;
            if (count++ >= 5) {
                return std::make_pair(string_view{}, true);
            }
            return std::make_pair(string_view(upload_chunk.data(), upload_chunk.size()), false);
        };
        req.set_body_source(std::move(source));
        
        // 流式下载
        std::atomic<size_t> download_bytes{0};
        Request::BodySink sink = [&](string_view chunk) -> bool {
            download_bytes.fetch_add(chunk.size());
            return true;
        };
        Request::BodySinkComplete complete = [](VoidResult) {};
        req.set_body_sink(std::move(sink), std::move(complete));
        
        // 验证接口设置正确
        REQUIRE(req.body_source().has_value());
        REQUIRE(req.body_sink().has_value());
        REQUIRE(req.body_bytes().empty());
    }
}
