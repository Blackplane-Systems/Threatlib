(function () {
  "use strict";

  function now() {
    return Date.now();
  }

  function createCollector(form, options) {
    var endpoint = options.endpoint;
    var accountId = options.accountId;
    var intervals = {};
    var lastKey = {};
    var pasteEvents = {};
    var tosScrolled = false;
    var backNavCount = 0;
    var externalLinks = [];
    var startedAt = now();

    function fieldName(target) {
      return target && (target.name || target.id);
    }

    form.addEventListener("keydown", function (event) {
      var name = fieldName(event.target);
      if (!name) return;
      var t = now();
      if (!intervals[name]) intervals[name] = [];
      if (lastKey[name]) intervals[name].push(t - lastKey[name]);
      lastKey[name] = t;
      if (event.key === "Backspace" || event.key === "Delete") backNavCount += 1;
    }, true);

    form.addEventListener("paste", function (event) {
      var name = fieldName(event.target);
      if (name) pasteEvents[name] = true;
    }, true);

    window.addEventListener("scroll", function () {
      tosScrolled = true;
    }, { passive: true });

    document.addEventListener("click", function (event) {
      var node = event.target;
      while (node && node.tagName !== "A") node = node.parentElement;
      if (!node || !node.href) return;
      try {
        var url = new URL(node.href, window.location.href);
        if (url.host && url.host !== window.location.host) externalLinks.push(url.host);
      } catch (error) {}
    }, true);

    function payload(extra) {
      var elapsed = Math.round((now() - startedAt) / 1000);
      return Object.assign({
        account_id: accountId,
        timing_field_intervals: intervals,
        timing_paste_events: pasteEvents,
        timing_tos_scrolled: tosScrolled,
        timing_back_nav_count: backNavCount,
        timing_registration_duration_s: elapsed,
        metadata: {
          external_link_domains: externalLinks,
          external_link_density: externalLinks.length > 0 ? 1 : 0
        }
      }, extra || {});
    }

    function submit(extra) {
      return fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload(extra))
      });
    }

    return { payload: payload, submit: submit };
  }

  window.ThreatLibTiming = { createCollector: createCollector };
}());
