# EasyPen Alpha 1.0

> Do not use EasyPen for illegal purposes, this tool is for research only

`EasyPen` is a GUI program which helps pentesters do information gathering, vulnerability scan and exploitation. 

It has more than 100 built-in scan scripts written in Python which covers most common vulnerabilities while at the same time it provides you some extra exploitation tools.

You can easily write your own python script and apply the scan for thousands of targets. 

请查看文档： https://easypen.lijiejie.com/

EasyPen 是使用Python + wxPython编写、提供简洁图形界面、支持跨平台的安全扫描工具，可用于企业内外网巡检、应急响应。主要功能包括：

* 资产发现：域名、IP、端口、服务等
* 漏洞扫描：基于AsyncIO实现的扫描框架，内置超过100个漏洞检测插件，支持调度Hydra/Medusa/Ncrack等工具扫描常见弱口令
* 应急响应：高危漏洞爆发后，依托框架和现成资产库，通常只需要编写十余行检测逻辑代码，就可以在几分钟内完成对数千目标的扫描
* 集成多个漏洞利用工具

![](ui/resource/screenshot.png)

![](ui/resource/easypen_tools.png)