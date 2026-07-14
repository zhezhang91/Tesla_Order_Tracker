# Tesla_Order_Tracker
Use this tool to track your Tesla order 
"""
Tesla 订单 / 交付追踪器(本地版)
================================
在你自己的电脑上运行,数据只在本机和特斯拉服务器之间传输,不经过任何第三方。

用法:
   
    pip install flask curl_cffi
    
    python tesla_tracker.py
    
    然后浏览器打开 http://localhost:8756
    ``

登录流程(和开源社区的做法一致):
1. 点击"登录特斯拉账号",在弹出的特斯拉官方页面登录
2. 登录成功后页面会跳到一个打不开的 tesla://auth/callback?... 地址(显示错误页是正常的)
3. 从浏览器地址栏 / 开发者工具复制那个完整地址,粘贴回本页面

为什么用 curl_cffi:特斯拉的登录接口会校验 TLS 指纹,
普通 requests 拿到的 token 会被 owner-api 拒绝(403),
curl_cffi 可以模拟真实 Chrome 的握手。

--------------------------------------------------------------------
Tesla Order / Delivery Tracker (local version)
================================
Runs entirely on your own computer; data only travels between this machine
and Tesla's servers, never through any third party.

Usage:

    pip install flask curl_cffi
    python tesla_tracker.py
    then open http://localhost:8756 in your browser

Login flow (matches what the open-source community does):
1. Click "Log in to Tesla account" and sign in on the official Tesla page
   that pops up
2. After a successful login, the page redirects to an unreachable
   tesla://auth/callback?... URL (seeing an error page here is expected)
3. Copy that full URL from the browser address bar / devtools and paste it
   back into this page

Why curl_cffi: Tesla's login endpoint checks the TLS fingerprint of the
client. A token obtained via plain `requests` gets rejected by owner-api
(403). curl_cffi can mimic a real Chrome TLS handshake.
"""
