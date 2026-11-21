#pragma once
// robots.txt per RFC 9309, with Google's documented interpretation where the
// RFC leaves room (user-agent token extraction, crawl-delay, common typos).

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wc::parse {

class RobotsRules {
public:
    // Selects the groups whose user-agent token equals `product_token`
    // case-insensitively (all such groups are merged); if there are none, all
    // "*" groups merged; if neither exists, everything is allowed.
    // `product_token` is the bare token, e.g. "wincrawl" (not a full UA).
    static RobotsRules parse(std::string_view body, std::string_view product_token);

    // `target` is a request target ("/path?query"). The longest matching
    // Allow/Disallow pattern decides; Allow wins ties; no match = allowed.
    // "/robots.txt" is always allowed.
    bool allowed(std::string_view target) const;

    // Crawl-delay (seconds) from the selected groups, if any.
    std::optional<double> crawl_delay() const { return crawl_delay_; }

    size_t rule_count() const { return rules_.size(); }

private:
    struct Rule {
        std::string pattern;  // percent-encoding normalized
        bool allow;
    };

    std::vector<Rule> rules_;
    std::optional<double> crawl_delay_;
};

}  // namespace wc::parse
