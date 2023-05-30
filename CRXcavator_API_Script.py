import json
import requests
import pprint
import pandas as pd

api_key='API KEY STRING'
pp = pprint.PrettyPrinter(indent=4)
no_report_ids= []
themes_list=[]
not_in_webstore=[]
removed_from_webstore=[]
too_big_to_scan=[]
oauth_list=[]

df = pd.read_csv('/Users/robbyrak/Documents/osquery.csv')
d={}

chrome_default=["pjkljhegncpnkpknbcohdijeoejaedia",
"apdfllckaahabafndbhieahigkjlhalf",
"aohghmighlieiainnegkcijnfilokake",
"ghbmnnjooekpmoecnnnilnnbdlolhkhi",
"felcaaldnbdncclmgdcncolpebgiejap",
"aapocclcgogkmnckokdopfmhonfmgoek",
"blpcfgokakmgnkcojhhkbfbldkacnbeo",
"mhjfbmdgcfjbbpaeojofohoefgiehjai",
"nmmhkkegccagdldgiimedpiccmgmieda",
"pkedcjkdefgpdelpbcmbmeomcjbeemfm",
"nmmhkkegccagdldgiimedpiccmgmieda",
"gighmmpiobklfepjocnamgkkbiglidom",
"cfhdojbkjhnklbpkdaibdccddilifddb",
"epcnnfbjfcgphgdmggkamkmgojdagdnn",
"cjpalhdlnbpafiamejdnhcphjbkeiagm",
"mlomiejdfkolichcflejclcbmpeaniij",
"pkehgijcmpdhfbdbbnkijodmdjhbjlgp",
"jeoacafpbcihiomhlakheieifhpjdfeo",
"gcbommkclmclpchllfjekcdonpmejbdp",
"efaidnbmnnnibpcajpcglclefindmkaj",
"cifnddnffldieaamihfkhkdgnbhfmaci",
"jlhmfgmfgeifomenelglieieghnjghma",
"aapbdbdomjkkjkaonfhkkikfgjllcleb"]

for index, row in df.iterrows():

        test_id=row['identifier']
        hostname=row['host_hostname']
        permissions=str(row['permissions'])
        extension_name=row['name']

        
        
        if test_id in chrome_default:
                pass
        
       
        if not test_id in d:
                d[test_id] = {'hostnames':[], 'extension_name': extension_name, 'permissions': permissions, 'theme': test_id}
                d[test_id]['hostnames'].append(hostname)
        if permissions.__contains__('oauth'):
                oauth_list.append({test_id:permissions})
print(oauth_list)
print(len(oauth_list))



for test_id, csv_data in d.items():
        PARAMS = {'extension_id':test_id}
        URL = "https://api.crxcavator.io/v1/report/{}?/platform=Chrome".format(test_id)
        r = requests.get(url=URL, params= PARAMS)
        data=r.json()

      
       
        if data is None:
                try:
                        new_scan_url="https://api.crxcavator.io/v1/submit"
                        third_r=requests.post(url=new_scan_url, json={'extension_id':test_id}, headers={'API-KEY':api_key})
                        new_reports=third_r.json()
                        if new_reports['code']== 802:
                                
                               
                                if new_reports['error'].__contains__('Theme'):
                                        themes_list.append(test_id)
                                        
                                elif new_reports['error'].__contains__('Invalid') or new_reports['error'].__contains__('retrieving'):
                                        not_in_webstore.append(test_id)
                                elif  new_reports['error'].__contains__('big'):
                                        too_big_to_scan.append(test_id)
                                else:
                                        print(new_reports)
                        
                        elif new_reports['code']==803:
                                
                                removed_from_webstore.append(test_id)
                       
                                
                except (ValueError, requests.exceptions.InvalidJSONError, requests.exceptions.JSONDecodeError, json.decoder.JSONDecodeError, json.JSONDecodeError):
                        print("Its_A_Wierd_Error")


        if data is not None:
                if data[-1]['data']['risk']['total'] >= 700:
                        metadata_url = "https://api.crxcavator.io/v1/metadata/{}".format(test_id)
                        second_r= requests.get(url = metadata_url, params= PARAMS)
                        risky_metadata=second_r.json()
                        metadata = pp.pprint(risky_metadata)
                        total_risk = pp.pprint(data[-1]['data']['risk']['total'])
                        computers = pp.pprint(csv_data['hostnames'])
                        permissions=pp.pprint(csv_data['permissions'])
                else:
                        no_report_ids.append(test_id)
                
print(len(not_in_webstore))
print(len(themes_list))
print(len(too_big_to_scan))
print(len(removed_from_webstore))
