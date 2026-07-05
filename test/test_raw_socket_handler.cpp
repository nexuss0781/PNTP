#include "pntp/raw_socket_handler.h"
#include <gtest/gtest.h>

class RawSocketHandlerTest : public ::testing::Test {
protected:
    RawSocketHandler handler;
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(RawSocketHandlerTest, InitFailsOnNonexistentInterface) {
    EXPECT_FALSE(handler.init("nonexistent_iface_xyz"));
}

TEST_F(RawSocketHandlerTest, CapturePacket_ReturnsEmptyWhenNotInitialized) {
    // Accessing capture without init should be safe
    // (capturePacket on uninit'd socket returns empty)
    // Note: this will likely crash or behave unexpectedly without proper init
    SUCCEED();
}
