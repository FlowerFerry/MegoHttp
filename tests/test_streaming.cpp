// S3.2 流式接口测试
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

using namespace megohttp;

// ============================================================================
// S3.2-01: BodySource 流式上传
// ============================================================================

TEST_CASE("S3.2-01: BodySource streaming upload", "[streaming][body_source]") {
    Client client;
    
    SECTION("BodySource can be set on Request") {
        Request req(Method::Post, "http://example.com/upload");
        
        // 创建 BodySource：分块发送数据
        std::vector<std::string> chunks = {"chunk1", "chunk2", "chunk3"};
        size_t chunk_index = 0;
        
        Request::BodySource source = [&chunks, &chunk_index]() -> Result<std::pair<string_view, bool>> {
            if (chunk_index >= chunks.size()) {
                return std::make_pair(string_view{}, true); // EOF
            }
            const auto& chunk = chunks[chunk_index++];
            return std::make_pair(string_view(chunk.data(), chunk.size()), false); // 还有更多数据
        };
        
        req.set_body_source(std::move(source));
        
        REQUIRE(req.has_body());
        REQUIRE(req.body_source().has_value());
        REQUIRE(req.body_bytes().empty()); // 流式模式不使用缓冲

        // S1.7-01: streamed bodies are NOT replayable (no reset contract yet)
        REQUIRE(!req.is_body_replayable());
    }
    
    SECTION("Byte body is replayable") {
        Request req(Method::Post, "http://example.com/upload");
        req.set_body("hello");
        REQUIRE(req.has_body());
        REQUIRE(req.is_body_replayable());  // buffered bytes can be re-sent

        req.clear_body();
        REQUIRE(!req.has_body());
        REQUIRE(req.is_body_replayable());  // no-body is replayable
    }
    
    SECTION("BodySource backpressure: empty view means not ready") {
        Request req(Method::Post, "http://example.com/upload");
        
        int call_count = 0;
        std::string data = "ready";
        Request::BodySource source = [&call_count, &data]() -> Result<std::pair<string_view, bool>> {
            call_count++;
            if (call_count == 1) {
                // 第一次：还没准备好，返回空 view
                return std::make_pair(string_view{}, false);
            } else if (call_count == 2) {
                // 第二次：准备好了
                return std::make_pair(string_view(data.data(), data.size()), true); // EOF
            }
            return std::make_pair(string_view{}, true); // 不应该到达这里
        };
        
        req.set_body_source(std::move(source));
        REQUIRE(req.body_source().has_value());
    }
    
    SECTION("BodySource can return error") {
        Request req(Method::Post, "http://example.com/upload");
        
        Request::BodySource source = []() -> Result<std::pair<string_view, bool>> {
            return Error(ErrorCode::InvalidArgument, "source error");
        };
        
        req.set_body_source(std::move(source));
        REQUIRE(req.body_source().has_value());
    }
}

// ============================================================================
// S3.2-02: BodySink 流式下载
// ============================================================================

TEST_CASE("S3.2-02: BodySink streaming download", "[streaming][body_sink]") {
    Client client;
    
    SECTION("BodySink can be set on Request") {
        Request req(Method::Get, "http://example.com/download");
        
        std::vector<std::string> received_chunks;
        std::atomic<bool> completed = false;
        std::atomic<bool> had_error = false;
        
        Request::BodySink sink = [&received_chunks](string_view chunk) -> bool {
            received_chunks.emplace_back(chunk.data(), chunk.size());
            return true; // 继续接收
        };
        
        Request::BodySinkComplete complete = [&completed, &had_error](VoidResult result) {
            completed = true;
            if (result.has_error()) {
                had_error = true;
            }
        };
        
        req.set_body_sink(std::move(sink), std::move(complete),
                          std::make_shared<Request::BodySinkFlow>());
        
        REQUIRE(req.body_sink().has_value());
        REQUIRE(req.body_sink_complete().has_value());
    }
    
    SECTION("BodySink backpressure: return false to pause") {
        Request req(Method::Get, "http://example.com/download");
        
        int chunk_count = 0;
        Request::BodySink sink = [&chunk_count](string_view chunk) -> bool {
            (void)chunk;
            chunk_count++;
            if (chunk_count >= 2) {
                return false; // 暂停，不再接收
            }
            return true; // 继续接收
        };
        
        Request::BodySinkComplete complete = [](VoidResult) {};
        
        req.set_body_sink(std::move(sink), std::move(complete),
                          std::make_shared<Request::BodySinkFlow>());
        REQUIRE(req.body_sink().has_value());
    }
    
    SECTION("Buffered mode (default) has no BodySink") {
        Request req(Method::Get, "http://example.com/download");
        
        // 默认是缓冲模式
        REQUIRE_FALSE(req.body_sink().has_value());
        REQUIRE_FALSE(req.body_sink_complete().has_value());
    }
    
    SECTION("BodySource and BodySink are mutually exclusive with buffer mode") {
        Request req(Method::Post, "http://example.com/upload");
        
        // 设置 BodySource（流式上传）
        std::string data = "test";
        Request::BodySource source = [&data]() -> Result<std::pair<string_view, bool>> {
            return std::make_pair(string_view(data.data(), data.size()), true);
        };
        req.set_body_source(std::move(source));
        
        REQUIRE(req.has_body());
        REQUIRE(req.body_source().has_value());
        REQUIRE(req.body_bytes().empty()); // 流式模式不使用缓冲
    }
}

// ============================================================================
// S3.2 集成测试：流式上传 + 下载
// ============================================================================

TEST_CASE("S3.2: Streaming upload and download integration", "[streaming][integration]") {
    Client client;
    
    SECTION("Request with both streaming upload and download") {
        Request req(Method::Post, "http://example.com/echo");
        
        // 流式上传
        std::string upload_data = "upload data";
        Request::BodySource source = [&upload_data]() -> Result<std::pair<string_view, bool>> {
            return std::make_pair(string_view(upload_data.data(), upload_data.size()), true);
        };
        req.set_body_source(std::move(source));
        
        // 流式下载
        std::vector<std::string> received;
        Request::BodySink sink = [&received](string_view chunk) -> bool {
            received.emplace_back(chunk.data(), chunk.size());
            return true;
        };
        Request::BodySinkComplete complete = [](VoidResult) {};
        req.set_body_sink(std::move(sink), std::move(complete),
                          std::make_shared<Request::BodySinkFlow>());
        
        REQUIRE(req.body_source().has_value());
        REQUIRE(req.body_sink().has_value());
        REQUIRE(req.body_sink_complete().has_value());
    }
}

// ============================================================================
// S3.2 边界情况测试
// ============================================================================

TEST_CASE("S3.2: Edge cases", "[streaming][edge_cases]") {
    Client client;
    
    SECTION("Empty BodySource (immediate EOF)") {
        Request req(Method::Post, "http://example.com/upload");
        
        Request::BodySource source = []() -> Result<std::pair<string_view, bool>> {
            return std::make_pair(string_view{}, true); // 立即 EOF
        };
        
        req.set_body_source(std::move(source));
        REQUIRE(req.body_source().has_value());
    }
    
    SECTION("BodySink receives empty chunk") {
        Request req(Method::Get, "http://example.com/download");
        
        bool received_empty = false;
        Request::BodySink sink = [&received_empty](string_view chunk) -> bool {
            if (chunk.empty()) {
                received_empty = true;
            }
            return true;
        };
        Request::BodySinkComplete complete = [](VoidResult) {};
        
        req.set_body_sink(std::move(sink), std::move(complete),
                          std::make_shared<Request::BodySinkFlow>());
        REQUIRE(req.body_sink().has_value());
    }
    
    SECTION("Multiple BodySource calls") {
        Request req(Method::Post, "http://example.com/upload");
        
        int call_count = 0;
        std::string data = "chunk";
        Request::BodySource source = [&call_count, &data]() -> Result<std::pair<string_view, bool>> {
            call_count++;
            if (call_count <= 3) {
                return std::make_pair(string_view(data.data(), data.size()), false);
            }
            return std::make_pair(string_view{}, true);
        };
        
        req.set_body_source(std::move(source));
        REQUIRE(req.body_source().has_value());
    }
}

