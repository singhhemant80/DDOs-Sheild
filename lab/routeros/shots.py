"""Screenshots of WebFig on the lab CHR."""
import sys, time
from playwright.sync_api import sync_playwright

OUT = sys.argv[1]
PAGES = [  # (file, menu path clicked in WebFig's left menu, tab)
    ("w-bgp-connections", ["Routing", "BGP"], "Connections"),
    ("w-bgp-sessions", ["Routing", "BGP"], "Sessions"),
    ("w-bgp-instances", ["Routing", "BGP"], "Instances"),
    ("w-filter-rules", ["Routing", "Filters"], None),
    ("w-routes", ["IP", "Routes"], None),
    ("w-raw", ["IP", "Firewall"], "Raw"),
    ("w-fw-filter", ["IP", "Firewall"], "Filter Rules"),
    ("w-users", ["System", "Users"], None),
    ("w-groups", ["System", "Users"], "Groups"),
]

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1440, "height": 860}, device_scale_factor=1.5)
    pg.goto("http://127.0.0.1:8080/webfig/")
    time.sleep(4)
    pg.screenshot(path=f"{OUT}/w-login.png")
    try:
        pg.fill("#name", "admin"); pg.fill("#password", "")
        pg.keyboard.press("Enter")
    except Exception as e:
        print("login form:", e)
    time.sleep(5)
    pg.screenshot(path=f"{OUT}/w-home.png")
    open(f"{OUT}/w-home.html", "w").write(pg.content())
    for name, menu, tab in PAGES:
        try:
            for m in menu:
                pg.get_by_text(m, exact=True).first.click(); time.sleep(1.5)
            if tab:
                pg.get_by_text(tab, exact=True).first.click(); time.sleep(1.5)
            time.sleep(2)
            pg.screenshot(path=f"{OUT}/{name}.png")
            print("ok", name)
        except Exception as e:
            print("FAIL", name, str(e).splitlines()[0])
            pg.screenshot(path=f"{OUT}/{name}-fail.png")
    b.close()
