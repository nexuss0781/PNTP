#include "pntp/performance_monitor.h"
#include <iostream>

PerformanceMonitor::PerformanceMonitor() : total_loss(0) {
    std::cout << "PerformanceMonitor initialized.\n";
}

void PerformanceMonitor::startMeasurement(const std::string& event_name) {
    start_times[event_name] = std::chrono::high_resolution_clock::now();
    std::cout << "Measurement started for: " << event_name << std::endl;
}

void PerformanceMonitor::endMeasurement(const std::string& event_name) {
    if (start_times.count(event_name)) {
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end_time - start_times[event_name];
        durations_ms[event_name] = duration.count();
        std::cout << "Measurement ended for: " << event_name << ", Duration: " << duration.count() << " ms" << std::endl;
    } else {
        std::cerr << "Warning: Measurement for " << event_name << " was not started.\n";
    }
}

double PerformanceMonitor::getDurationMs(const std::string& event_name) const {
    if (durations_ms.count(event_name)) {
        return durations_ms.at(event_name);
    }
    return 0.0;
}

void PerformanceMonitor::recordPacketLoss(const std::string& connection_id, int lost_count) {
    packet_loss_counts[connection_id] += lost_count;
    total_loss += lost_count;
    std::cout << "Recorded " << lost_count << " packet loss(es) for connection: " << connection_id << std::endl;
}

int PerformanceMonitor::getTotalPacketLoss() const {
    return total_loss;
}

long long PerformanceMonitor::getHighPrecisionTimestampAssembly() const {
    // Conceptual representation of an assembly-optimized timestamp.
    // In a real scenario, this would involve inline assembly or platform-specific intrinsics
    // like RDTSC (Read Time-Stamp Counter) on x86-64 for very high-resolution timing.
    // For this educational purpose, we'll return a high-resolution C++ timestamp.
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}
