<div align="center">
<img src="ui/resource/readme_logo.png" />
</div>

# EasyPen Alpha 1.0.4

> Do not use EasyPen for illegal purposes, this tool is for research only

[查看中文](https://github.com/lijiejie/EasyPen/blob/main/README_CN.md) 

`EasyPen` is a GUI program which helps pentesters do target discovery, vulnerability scan and exploitation.

It has over 100 built-in scan scripts which covers most common vulnerabilities, you can easily write your own scan script and map the scan for thousands of targets. 

**User Manual**： https://easypen.lijiejie.com/      

### Change Log

* 2022-09-16: Bug Fix: Targets input missing `is_http`.
* 2022-09-15: Bug Fix: DNS log monitor object overwrite, brute job shouldn't create dns log monitor.
* 2022-09-13: Bug fix: hydra plugin works with a hard code `timeout`. 
* 2022-09-12: important bug fix, asyncio timeout failed to gather returned vulnerabilities. 

### Install

Microsoft Windows users can download zipped file and run `EasyPen.exe` : https://github.com/lijiejie/EasyPen/releases

Users who are familiar with python can install via pip3

```
pip3 install -r requirements.txt
```

> At present this project is developed and tested under Python3.8, please use Python3.8 to run this app

### Feathers

* **Discover**: Domain / IP / Port / Services discovery,  build assert databases
* **Vulnerability Scan**：Single thread scan framework works with AsyncIO, with over 100 built-in plugins, can driven Hydra/Medusa/Ncrack to brute weak passwords
* **Incident Response**：Whenever a critical vulnerability was disclosed, based on the assert db created by the discover module and the scan framework, in most cases, users only need to write very few lines of code to implement the vulnerability check.  After that you can map the scan script to thousands of targets and finish the scan in serveral minutes.
* **Exploitation**: Provides you some exploit tools



**Scan Panel Screenshot**

![](ui/resource/screenshot.png)



**Tools Panel Screenshot**

![](ui/resource/easypen_tools.png)

### Develop Plans

Alpha 1.0 was released, includes some basic modules. Please create issues if any bugs found.  

* Adapt more DNSLog APIs，includes [Antenna漏洞验证平台](https://github.com/wuba/Antenna) 
* Web fingerprints and live preview
* scan plugin profiles
* Support the execution of other open source projects' scan plugins:  python / YAML
* Plugin live edit and debug
* Vulnerabilities one click recheck
* Brute function optimization
* Integrate with BBScan
* Better scan performance and algorithm
* Better code construction, more friendly for other users to contribute plugin & tools