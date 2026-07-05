#include "pntp/performance_monitor.h"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

class PerformanceMonitorTest : public ::testing::Test {
protected:
    PerformanceMonitor monitor;
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(PerformanceMonitorTest, StartEndMeasurement_ReturnsPositiveDuration) {
    monitor.startMeasurement("test_event");
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    monitor.endMeasurement("test_event");
    double duration = monitor.getDurationMs("test_event");
    EXPECT_GT(duration, 0.0);
}

TEST_F(PerformanceMonitorTest, GetDurationMs_UnmeasuredEvent_ReturnsZero) {
    double duration = monitor.getDurationMs("nonexistent");
    EXPECT_DOUBLE_EQ(duration, 0.0);
}

TEST_F(PerformanceMonitorTest, RecordPacketLoss_AccumulatesCount) {
    EXPECT_EQ(monitor.getTotalPacketLoss(), 0);
    monitor.recordPacketLoss("conn1", 1);
    EXPECT_EQ(monitor.getTotalPacketLoss(), 1);
    monitor.recordPacketLoss("conn1", 2);
    EXPECT_EQ(monitor.getTotalPacketLoss(), 3);
    monitor.recordPacketLoss("conn2", 5);
    EXPECT_EQ(monitor.getTotalPacketLoss(), 8);
}

TEST_F(PerformanceMonitorTest, GetHighPrecisionTimestamp_ReturnsNonZero) {
    long long ts = monitor.getHighPrecisionTimestampAssembly();
    EXPECT_GT(ts, 0);
}

TEST_F(PerformanceMonitorTest, SequentialMeasurements_Independent) {
    monitor.startMeasurement("event_a");
    monitor.startMeasurement("event_b");
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    monitor.endMeasurement("event_b");
    monitor.endMeasurement("event_a");

    double dur_a = monitor.getDurationMs("event_a");
    double dur_b = monitor.getDurationMs("event_b");
    EXPECT_GT(dur_a, 0.0);
    EXPECT_GT(dur_b, 0.0);
}
