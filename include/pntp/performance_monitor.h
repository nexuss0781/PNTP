#ifndef PERFORMANCE_MONITOR_H
#define PERFORMANCE_MONITOR_H

#include <chrono>
#include <string>
#include <map>

class PerformanceMonitor {
public:
    PerformanceMonitor();

    void startMeasurement(const std::string& event_name);
    void endMeasurement(const std::string& event_name);
    double getDurationMs(const std::string& event_name) const;

    void recordPacketLoss(const std::string& connection_id, int lost_count = 1);
    int getTotalPacketLoss() const;

    // Conceptual method for assembly-optimized timing
    long long getHighPrecisionTimestampAssembly() const;

private:
    std::map<std::string, std::chrono::high_resolution_clock::time_point> start_times;
    std::map<std::string, double> durations_ms;
    std::map<std::string, int> packet_loss_counts;
    int total_loss;
};

#endif // PERFORMANCE_MONITOR_H
