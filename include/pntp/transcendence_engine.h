#ifndef TRANSCENDENCE_ENGINE_H
#define TRANSCENDENCE_ENGINE_H

#include <string>
#include <vector>

struct UdacityCourseData {
    std::string course_title;
    std::string lesson_name;
    std::string video_url;
    std::vector<std::string> sibling_courses;
};

class BackendTranscendence {
public:
    BackendTranscendence();
    UdacityCourseData transcendAndFetch(const std::string& url);

private:
    void simulateNetworkBypass(const std::string& url);
    std::string extractActualData(const std::string& raw_stream);
};

#endif // TRANSCENDENCE_ENGINE_H
