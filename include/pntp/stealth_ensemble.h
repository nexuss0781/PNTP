#ifndef STEALTH_ENSEMBLE_H
#define STEALTH_ENSEMBLE_H

#include <string>
#include <vector>
#include <map>

class StealthEnsemble {
public:
    StealthEnsemble();
    ~StealthEnsemble();

    bool initializeEnsemble();
    void applyStealthLayer(const std::string& layer_name);
    std::string processRequestThroughEnsemble(const std::string& url);
    
    // Advanced networking layer functions
    void injectNoisePackets();
    void randomizeHopLimits();
    void spoofTcpFingerprint();

private:
    std::vector<std::string> active_layers;
    std::map<std::string, std::string> layer_configs;
};

#endif // STEALTH_ENSEMBLE_H
