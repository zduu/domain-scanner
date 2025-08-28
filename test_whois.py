#!/usr/bin/env python3

import whois
import sys

def query_domain(domain):
    print(f"查询域名: {domain}")
    
    try:
        # 使用 python-whois 库查询
        result = whois.whois(domain)
        
        print("WHOIS 信息:")
        print(f"  域名: {result.domain_name}")
        print(f"  注册商: {result.registrar}")
        print(f"  创建日期: {result.creation_date}")
        print(f"  过期日期: {result.expiration_date}")
        print(f"  状态: {result.status}")
        print(f"  名称服务器: {result.name_servers}")
        
        # 打印原始响应
        print("\n原始 WHOIS 响应:")
        print(result.text if hasattr(result, 'text') else "无原始响应文本")
        
    except Exception as e:
        print(f"查询出错: {e}")
        
        # 尝试使用命令行 whois 工具
        import subprocess
        try:
            print("\n尝试使用系统 whois 命令...")
            output = subprocess.check_output(['whois', domain], stderr=subprocess.STDOUT, universal_newlines=True)
            print(output)
        except Exception as e2:
            print(f"系统 whois 命令也失败了: {e2}")

if __name__ == "__main__":
    domain = "bun.de"
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    
    query_domain(domain)