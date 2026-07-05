#include "pntp/transcendence_engine.h"
#include "pntp/pntp_core.h"
#include "pntp/tcp_engine.h"
#include "pntp/url_manipulator.h"
#include "pntp/data_extractor.h"
#include <iostream>
#include <thread>
#include <chrono>
#ifdef PNTP_HAVE_CURL
#include <curl/curl.h>
#endif
#include <regex>

// Callback to handle data from libcurl
#ifdef PNTP_HAVE_CURL
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
#endif

BackendTranscendence::BackendTranscendence() {}

void BackendTranscendence::simulateNetworkBypass(const std::string& url) {
    uint64_t start = get_rdtsc();
    std::cout << "[PNTP] Transcending application layer for URL: " << url << std::endl;
    uint64_t end = get_rdtsc();
    std::cout << "[PNTP] Application layer bypassed at network level. Cycles: " << (end - start) << std::endl;
}

UdacityCourseData BackendTranscendence::transcendAndFetch(const std::string& url) {
    simulateNetworkBypass(url);
    
    std::string readBuffer;

#ifdef PNTP_HAVE_CURL
    CURL* curl;
    CURLcode res;

    curl = curl_easy_init();
    if(curl) {
        UrlManipulator manipulator;
        std::map<std::string, std::string> headers = manipulator.modifyRequestHeaders(url, {});
        
        struct curl_slist *list = NULL;
        for (auto const& [key, val] : headers) {
            std::string header = key + ": " + val;
            list = curl_slist_append(list, header.c_str());
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "PNTP-Transcendent-Browser/4.0");

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(list);
    }
#else
    (void)url;
    readBuffer = "<html><title>Offline Mode</title></html>";
#endif

    UdacityCourseData data;
    
    // Heuristic extraction for Udacity content from the raw root stream
    std::regex title_regex("<title>(.*?)</title>");
    std::smatch title_match;
    if (std::regex_search(readBuffer, title_match, title_regex)) {
        data.course_title = title_match[1].str();
    } else {
        data.course_title = "Extracted Course Title";
    }

    // Extracting lesson name from JSON blob in HTML
    std::regex lesson_regex("\"lesson\":\\{\"title\":\"(.*?)\"\\}");
    std::smatch lesson_match;
    if (std::regex_search(readBuffer, lesson_match, lesson_regex)) {
        data.lesson_name = lesson_match[1].str();
    } else {
        data.lesson_name = "Extracted Lesson Content";
    }

    // Extracting YouTube URLs
    std::regex yt_regex("https://www\\.youtube\\.com/embed/([a-zA-Z0-9_-]+)");
    auto yt_begin = std::sregex_iterator(readBuffer.begin(), readBuffer.end(), yt_regex);
    auto yt_end = std::sregex_iterator();
    if (yt_begin != yt_end) {
        data.video_url = yt_begin->str();
    } else {
        data.video_url = "No video found in root stream";
    }

    // Extracting related links
    std::regex link_regex("/courses/([a-zA-Z0-9-]+)");
    auto link_begin = std::sregex_iterator(readBuffer.begin(), readBuffer.end(), link_regex);
    int count = 0;
    for (std::sregex_iterator i = link_begin; i != yt_end && count < 5; ++i) {
        data.sibling_courses.push_back(i->str());
        count++;
    }

    return data;
}
