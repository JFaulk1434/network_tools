import speedtest

s = speedtest.Speedtest()
download = s.download()
print(download)
