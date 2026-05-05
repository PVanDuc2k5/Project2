import requests
import my_scanner  
import urllib.parse 
import time


def check_cve(product):
 if not product:
        print("Bỏ qua vì không có tên dịch vụ.")
        return
 product = product.split()[0]
 safe_product = urllib.parse.quote(product, safe='')   
 url=f"https://cve.circl.lu/api/search/{safe_product}/{safe_product}"
 try:
    response=requests.get(url)
    if response.status_code==200:
        data=response.json()
        cve_list=data.get('results',{}).get('cvelistv5',[])
        if cve_list:
            for cve in cve_list:
                print( f"\n{cve[0]}")
        else:
            print("Không tìm thấy CVE trên API (Lưu ý: Vẫn có thể bị lỗi cấu hình/mật khẩu yếu)")
    else:
        print(f"[-] Lỗi API: {response.status_code}")
 except Exception as e:
  print(f"Đã xảy ra sự cố mạng: {e}")
  time.sleep(1) 