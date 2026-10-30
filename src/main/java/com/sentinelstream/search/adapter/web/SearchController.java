package com.sentinelstream.search.adapter.web;

import com.sentinelstream.search.application.SearchService;
import com.sentinelstream.shared.security.Actors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;

@RestController
class SearchController {

    private final SearchService search;

    SearchController(SearchService search) {
        this.search = search;
    }

    @GetMapping("/v1/events/search")
    SearchService.Page search(@RequestParam(required = false) String user, @RequestParam(required = false) String ip,
                              @RequestParam(required = false) String action,
                              @RequestParam(required = false) String outcome,
                              @RequestParam(required = false) Instant from, @RequestParam(required = false) Instant to,
                              @RequestParam(required = false) Integer limit,
                              @RequestParam(required = false) String cursor,
                              @RequestParam(defaultValue = "false") boolean unmasked) {
        var filters = new LinkedHashMap<String, String>();
        if (user != null) {
            filters.put("user", user);
        }
        if (ip != null) {
            filters.put("ip", ip);
        }
        if (action != null) {
            filters.put("action", action);
        }
        if (outcome != null) {
            filters.put("outcome", outcome);
        }
        return search.search(Actors.current(), filters, from, to, limit, cursor, unmasked);
    }
}
