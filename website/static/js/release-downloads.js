(function () {
  var API_URL =
    "https://api.github.com/repos/ghostunnel/ghostunnel/releases?per_page=100";

  var OS_LABELS = {
    linux: "Linux",
    darwin: "macOS",
    windows: "Windows",
  };

  var ARCH_LABELS = {
    amd64: "x86_64",
    arm64: "ARM64",
    universal: "Universal",
  };

  function parseAssetName(name) {
    // Expected: ghostunnel-{os}-{arch}[.exe]
    var m = name.match(/^ghostunnel-(\w+)-(\w+?)(\.exe)?$/);
    if (!m) return null;
    return { os: m[1], arch: m[2], exe: !!m[3] };
  }

  function renderDownloads(container, assets) {
    // Group by OS
    var byOS = {};
    assets.forEach(function (a) {
      var info = parseAssetName(a.name);
      if (!info) return;
      if (!byOS[info.os]) byOS[info.os] = [];
      byOS[info.os].push({ info: info, url: a.browser_download_url, name: a.name, size: a.size });
    });

    var osOrder = ["linux", "darwin", "windows"];
    var items = [];

    osOrder.forEach(function (os) {
      if (!byOS[os]) return;
      byOS[os].forEach(function (asset) {
        var label = OS_LABELS[asset.info.os] || asset.info.os;
        var arch = ARCH_LABELS[asset.info.arch] || asset.info.arch;
        var sizeMB = (asset.size / (1024 * 1024)).toFixed(1);
        items.push(
          '<a class="download-link" href="' + asset.url + '" title="' + asset.name + '">' +
            '<span class="download-os">' + label + '</span> ' +
            '<span class="download-arch">' + arch + '</span>' +
            '<span class="download-size">' + sizeMB + ' MB</span>' +
          "</a>"
        );
      });
    });

    if (items.length === 0) return;

    container.innerHTML =
      '<div class="download-bar">' +
        '<span class="download-label">Downloads</span>' +
        '<span class="download-items">' + items.join("") + '</span>' +
      "</div>";
  }

  function populate(releases) {
    var tagMap = {};
    releases.forEach(function (r) {
      if (r.assets && r.assets.length > 0) {
        tagMap[r.tag_name] = r.assets;
      }
    });

    var containers = document.querySelectorAll(".release-downloads[data-tag]");
    containers.forEach(function (el) {
      var tag = el.getAttribute("data-tag");
      if (tagMap[tag]) {
        renderDownloads(el, tagMap[tag]);
      }
    });
  }

  // Fetch all releases (up to 100, which covers all current releases)
  fetch(API_URL)
    .then(function (res) {
      if (!res.ok) return [];
      return res.json();
    })
    .then(populate)
    .catch(function () {
      // Silently fail — GitHub/Docker links in the header are the fallback
    });
})();
