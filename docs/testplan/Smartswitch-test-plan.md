# Test plan for Smartswitch

- [Introduction](#introduction)
- [Scope](#scope)
- [Definitions and Abbreviations](#definitions-and-abbreviations)
- [Objectives of CLI Test Cases](#objectives-of-cli-test-cases)
- [CLI Test Cases](#cli-test-cases)
    - [1.1 Check DPU Status](#11-check-dpu-status)
    - [1.2 Check platform voltage](#12-check-platform-voltage)
    - [1.3 Check platform temperature](#13-check-platform-temperature)
    - [1.4 Check DPU console](#14-check-DPU-console)
    - [1.5 Check midplane ip address between NPU and DPU](#15-check-midplane-ip-address-between-npu-and-dpu)
    - [1.6 Check DPU shutdown and power up individually](#16-check-DPU-shutdown-and-power-up-individually)
    - [1.7 Check removal of pcie link between NPU and DPU](#17-check-removal-of-pcie-link-between-npu-and-dpu)
    - [1.8 Check the NTP date and timezone between DPU and NPU](#18-check-the-ntp-date-and-timezone-between-dpu-and-npu)
    - [1.9 Check the State of DPUs](#19-check-the-state-of-dpus)
    - [1.10 Check the Health of DPUs](#110-check-the-health-of-dpus)
    - [1.11 Check reboot cause history](#111-check-reboot-cause-history)
    - [1.12 Check the DPU state after OS reboot](#112-check-the-dpu-state-after-os-reboot)
- [Objectives of API Test Cases](#objectives-of-api-test-cases)
- [API Test Cases](#api-test-cases)
    - [1.1 Check SmartSwitch specific ChassisClass APIs](#11-check-smartswitch-specific-chassisclass-apis)
    - [1.2 Check modified ChassisClass APIs for smartswitch](#12-check-modified-chassisclass-apis-for-smartswitch)
    - [1.3 Check DpuModule APIs for SmartSwitch](#13-check-dpumodule-apis-for-smartswitch)
    - [1.4 Check modified ModuleClass APIs](#14-check-modified-moduleclass-apis)

## Introduction

The purpose is to test the functionality of Smartswitch.
Smartswitch is connected to DPUs via pcie links.

## Scope

The test is targeting a running SONIC on Switch and SONIC-DASH system on each DPUs. 
Purpose of the test is to verify smartswich platform related functionalities/features for each DPUs and PMON APIs. 
For every test cases, all DPUs need to be powered on unless specified in any of the case.

## Definitions and Abbreviations

| **Term**   | **Meaning**                              |
| ---------- | ---------------------------------------- |
| DPU       | Data Processing Unit       |
| NPU       | Network Processing Unit       |
| NTP       | Network Time Protocol       |
| SWITCH    | Refers to NPU and the anything other than DPUs    |
| SS        | SmartSwitch       |

## Objectives of CLI Test Cases

|    | **Test Case**   | **Intention**                              | **Comments** |
| ---------- | ---------- | ---------------------------------------- | ---------- |
| 1.1 | Check DPU Status       | To verify the DPU Status shown in the cli | |
| 1.2 | Check platform voltage       |  To verify the Voltage sensor values and and functionality of alarm by changing the threshold values | |
| 1.3 | Check platform temperature       |  To Verify the Temperature sensor values and functionality of alarm by changing the threshold values | |
| 1.4 | Check DPU console       | To Verify console access for all DPUs       | |
| 1.5 | Check midplane ip address between NPU and DPU      | To Verify PCIe interface created between NPU and DPU according to bus number | |
| 1.6 | Check DPU shutdown and power up individually      |  To Verify DPU shutdown and DPUs power up | |
| 1.7 | Check removal of pcie link between NPU and DPU       | To Verify the PCie hot plug functinality        | |
| 1.8 | Check the NTP date and timezone between DPU and NPU       | To Verify NPU and DPU are in sync with respect to timezone and logs timestamp | |
| 1.9 | Check the State of DPUs      | To Verify DPU state details during online and offline      | |
| 1.10 | Check the Health of DPUs       | To Verify overall health (LED, process, docker, services and hw) of DPU | Phase:2 |
| 1.11 | Check reboot cause history       | To Verify reboot cause history cli | |
| 1.12 | Check the DPU state after OS reboot       | To Verify DPU state on host reboot | |


## CLI Test Cases

### 1.1 Check DPU Status

#### Steps
 * Use command `show chassis modules status` to get DPU status 
 * Get the number of DPU modules from PMON APIs - get_num_modules()

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:
root@sonic:/home/cisco# show chassis modules status
  Name    Description    Physical-Slot    Oper-Status    Admin-Status    Serial
------  -------------  ---------------  -------------  --------------  --------
  DPU0            N/A               -1         Online              up       N/A
  DPU1            N/A               -1         Online              up       N/A
  DPU2            N/A               -1         Online              up       N/A
  DPU3            N/A               -1         Online              up       N/A
  DPU4            N/A               -1         Online              up       N/A
  DPU5            N/A               -1         Online              up       N/A
  DPU6            N/A               -1         Online              up       N/A
  DPU7            N/A               -1         Online              up       N/A

```
#### Pass/Fail Criteria
 *  Verify number of DPUs from api and number of DPUs shown in the cli output.


### 1.2 Check platform voltage

#### Steps
 * Use command `show platform voltage` to get platform voltage

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:

root@sonic:/home/cisco# show platform voltage
                  Sensor    Voltage    High TH    Low TH    Crit High TH    Crit Low TH    Warning          Timestamp
------------------------  ---------  ---------  --------  --------------  -------------  ---------  -----------------
                 A1V2_BB    1211 mV       1308      1092            1320           1080      False  20230619 11:31:08
                 A1V8_BB    1810 mV       1962      1638            1980           1620      False  20230619 11:31:07
                  A1V_BB    1008 mV       1090       910            1100            900      False  20230619 11:31:06
                 A1V_CPU    1001 mV       1090       910            1100            900      False  20230619 11:31:51
               A1_2V_CPU    1209 mV       1308      1092            1320           1080      False  20230619 11:31:52
               A1_8V_CPU    1803 mV       1962      1638            1980           1620      False  20230619 11:31:51
               A2_5V_CPU    2517 mV       2725      2275            2750           2250      False  20230619 11:31:52
               A3P3V_CPU    3284 mV       3597      3003            3603           2970      False  20230619 11:31:53
                 A3V3_BB    3298 mV       3597      3003            3630           2970      False  20230619 11:31:08
       GB_CORE_VIN_L1_BB   12000 mV      13800     10200           14400           9600      False  20230619 11:31:06
      GB_CORE_VOUT_L1_BB     824 mV        N/A       614             918            608      False  20230619 11:31:50
       GB_P1V8_PLLVDD_BB    1812 mV       1962      1638            1980           1620      False  20230619 11:31:11
        GB_P1V8_VDDIO_BB    1815 mV       1962      1638            1980           1620      False  20230619 11:31:11
       GB_PCIE_VDDACK_BB     755 mV        818       683             825            675      False  20230619 11:31:12
         GB_PCIE_VDDH_BB    1208 mV       1308      1092            1320           1080      False  20230619 11:31:12
                P3_3V_BB    3330 mV       3597      3003            3630           2970      False  20230619 11:31:12
                  P5V_BB    5069 mV       5450      4550            5500           4500      False  20230619 11:31:07
                P12V_CPU   12103 mV      13080     10920           13200          10800      False  20230619 11:31:54
          P12V_SLED1_VIN   12048 mV        N/A       N/A           12550          11560      False  20230619 11:31:13
          P12V_SLED2_VIN   12048 mV        N/A       N/A           12550          11560      False  20230619 11:31:13
          P12V_SLED3_VIN   12079 mV        N/A       N/A           12550          11560      False  20230619 11:31:13
          P12V_SLED4_VIN   12043 mV        N/A       N/A           12550          11560      False  20230619 11:31:13
           P12V_STBY_CPU   12103 mV      13080     10920           13200          10800      False  20230619 11:31:54
         P12V_U1_VR3_CPU   11890 mV      13800     10200           14400           9600      False  20230619 11:31:54
         P12V_U1_VR4_CPU   11890 mV        N/A       N/A             N/A            N/A      False  20230619 11:31:54
         P12V_U1_VR5_CPU   11890 mV      13800     10200           14400           9600      False  20230619 11:31:54
         TI_3V3_L_VIN_BB   12015 mV        N/A     10200           14400           9600      False  20230619 11:31:06
     TI_3V3_L_VOUT_L1_BB    3340 mV        N/A      2839            4008           2672      False  20230619 11:31:13
         TI_3V3_R_VIN_BB   12078 mV        N/A     10200           14400           9600      False  20230619 11:31:06
     TI_3V3_R_VOUT_L1_BB    3340 mV        N/A      2839            4008           2672      False  20230619 11:31:13
   TI_GB_VDDA_VOUT_L2_BB     960 mV        N/A       816            1152            768      False  20230619 11:31:13
      TI_GB_VDDCK_VIN_BB   12031 mV        N/A     10200           14400           9600      False  20230619 11:31:06
  TI_GB_VDDCK_VOUT_L1_BB    1150 mV        N/A       978            1380            920      False  20230619 11:31:13
       TI_GB_VDDS_VIN_BB   12046 mV        N/A     10200           14400           9600      False  20230619 11:31:50
   TI_GB_VDDS_VOUT_L1_BB     750 mV        N/A       638             900            600      False  20230619 11:31:12
     VP0P6_DDR0_VTT_DPU0     599 mV        630       570             642            558      False  20230619 11:31:55
     VP0P6_DDR0_VTT_DPU1     597 mV        630       570             642            558      False  20230619 11:31:56
     VP0P6_DDR0_VTT_DPU2     600 mV        630       570             642            558      False  20230619 11:31:58
     VP0P6_DDR0_VTT_DPU3     600 mV        630       570             642            558      False  20230619 11:31:59
     VP0P6_DDR0_VTT_DPU4     599 mV        630       570             642            558      False  20230619 11:32:01
     VP0P6_DDR0_VTT_DPU5     597 mV        630       570             642            558      False  20230619 11:31:02
     VP0P6_DDR0_VTT_DPU6     596 mV        630       570             642            558      False  20230619 11:31:04
     VP0P6_DDR0_VTT_DPU7     599 mV        630       570             642            558      False  20230619 11:31:05
     VP0P6_DDR1_VTT_DPU0     600 mV        630       570             642            558      False  20230619 11:31:56
     VP0P6_DDR1_VTT_DPU1     602 mV        630       570             642            558      False  20230619 11:31:57
     VP0P6_DDR1_VTT_DPU2     601 mV        630       570             642            558      False  20230619 11:31:58
     VP0P6_DDR1_VTT_DPU3     601 mV        630       570             642            558      False  20230619 11:32:00
     VP0P6_DDR1_VTT_DPU4     600 mV        630       570             642            558      False  20230619 11:31:02
     VP0P6_DDR1_VTT_DPU5     597 mV        630       570             642            558      False  20230619 11:31:03
     VP0P6_DDR1_VTT_DPU6     596 mV        630       570             642            558      False  20230619 11:31:04
     VP0P6_DDR1_VTT_DPU7     601 mV        630       570             642            558      False  20230619 11:31:06
      VP0P6_VTT_DIMM_CPU     597 mV        654       546             660            540      False  20230619 11:31:51
      VP0P8_AVDD_D6_DPU0     801 mV        840       760             856            744      False  20230619 11:31:16
  VP0P8_AVDD_D6_DPU1_ADC     806 mV        840       760             856            744      False  20230619 11:31:20
      VP0P8_AVDD_D6_DPU2     804 mV        840       760             856            744      False  20230619 11:31:25
  VP0P8_AVDD_D6_DPU3_ADC     805 mV        840       760             856            744      False  20230619 11:31:29
      VP0P8_AVDD_D6_DPU4     806 mV        840       760             856            744      False  20230619 11:31:34
  VP0P8_AVDD_D6_DPU5_ADC     801 mV        840       760             856            744      False  20230619 11:31:39
      VP0P8_AVDD_D6_DPU6     805 mV        840       760             856            744      False  20230619 11:31:44
  VP0P8_AVDD_D6_DPU7_ADC     806 mV        840       760             856            744      False  20230619 11:31:48
           VP0P8_NW_DPU0     803 mV        840       760             856            744      False  20230619 11:31:17
           VP0P8_NW_DPU1     804 mV        840       760             856            744      False  20230619 11:31:21
           VP0P8_NW_DPU2     803 mV        840       760             856            744      False  20230619 11:31:26
           VP0P8_NW_DPU3     804 mV        840       760             856            744      False  20230619 11:31:31
           VP0P8_NW_DPU4     805 mV        840       760             856            744      False  20230619 11:31:35
           VP0P8_NW_DPU5     801 mV        840       760             856            744      False  20230619 11:31:40
           VP0P8_NW_DPU6     801 mV        840       760             856            744      False  20230619 11:31:45
           VP0P8_NW_DPU7     804 mV        840       760             856            744      False  20230619 11:31:49
VP0P8_PLL_AVDD_PCIE_DPU0     802 mV        840       760             856            744      False  20230619 11:31:56
VP0P8_PLL_AVDD_PCIE_DPU1     804 mV        840       760             856            744      False  20230619 11:31:57
VP0P8_PLL_AVDD_PCIE_DPU2     801 mV        840       760             856            744      False  20230619 11:31:59
VP0P8_PLL_AVDD_PCIE_DPU3     802 mV        840       760             856            744      False  20230619 11:32:00
VP0P8_PLL_AVDD_PCIE_DPU4     804 mV        840       760             856            744      False  20230619 11:31:02
VP0P8_PLL_AVDD_PCIE_DPU5     800 mV        840       760             856            744      False  20230619 11:31:03
VP0P8_PLL_AVDD_PCIE_DPU6     799 mV        840       760             856            744      False  20230619 11:31:05
VP0P8_PLL_AVDD_PCIE_DPU7     802 mV        840       760             856            744      False  20230619 11:31:06
     VP0P9_AVDDH_D6_DPU0     906 mV        945       855             963            837      False  20230619 11:31:15
     VP0P9_AVDDH_D6_DPU1     908 mV        945       855             963            837      False  20230619 11:31:19
     VP0P9_AVDDH_D6_DPU2     907 mV        945       855             963            837      False  20230619 11:31:24
     VP0P9_AVDDH_D6_DPU3     908 mV        945       855             963            837      False  20230619 11:31:29
     VP0P9_AVDDH_D6_DPU4     910 mV        945       855             963            837      False  20230619 11:31:33
     VP0P9_AVDDH_D6_DPU5     911 mV        945       855             963            837      False  20230619 11:31:38
     VP0P9_AVDDH_D6_DPU6     908 mV        945       855             963            837      False  20230619 11:31:43
     VP0P9_AVDDH_D6_DPU7     907 mV        945       855             963            837      False  20230619 11:31:47
   VP0P9_AVDDH_PCIE_DPU0     901 mV        945       855             963            837      False  20230619 11:31:17
   VP0P9_AVDDH_PCIE_DPU1     903 mV        945       855             963            837      False  20230619 11:31:22
   VP0P9_AVDDH_PCIE_DPU2     901 mV        945       855             963            837      False  20230619 11:31:26
   VP0P9_AVDDH_PCIE_DPU3     903 mV        945       855             963            837      False  20230619 11:31:31
   VP0P9_AVDDH_PCIE_DPU4     902 mV        945       855             963            837      False  20230619 11:31:36
   VP0P9_AVDDH_PCIE_DPU5     901 mV        945       855             963            837      False  20230619 11:31:40
   VP0P9_AVDDH_PCIE_DPU6     902 mV        945       855             963            837      False  20230619 11:31:45
   VP0P9_AVDDH_PCIE_DPU7     903 mV        945       855             963            837      False  20230619 11:31:50
        VP0P75_PVDD_DPU0     752 mV        788       713             803            698      False  20230619 11:31:15
        VP0P75_PVDD_DPU1     756 mV        788       713             802            698      False  20230619 11:31:20
        VP0P75_PVDD_DPU2     756 mV        788       713             803            698      False  20230619 11:31:24
        VP0P75_PVDD_DPU3     755 mV        788       713             802            698      False  20230619 11:31:29
        VP0P75_PVDD_DPU4     756 mV        788       713             803            698      False  20230619 11:31:34
        VP0P75_PVDD_DPU5     757 mV        788       713             802            698      False  20230619 11:31:38
        VP0P75_PVDD_DPU6     756 mV        788       713             803            698      False  20230619 11:31:43
        VP0P75_PVDD_DPU7     756 mV        788       713             802            698      False  20230619 11:31:47
       VP0P75_RTVDD_DPU0     753 mV        788       713             803            698      False  20230619 11:31:14
       VP0P75_RTVDD_DPU1     755 mV        788       713             802            698      False  20230619 11:31:19
       VP0P75_RTVDD_DPU2     752 mV        788       713             803            698      False  20230619 11:31:24
       VP0P75_RTVDD_DPU3     755 mV        788       713             802            698      False  20230619 11:31:28
       VP0P75_RTVDD_DPU4     753 mV        788       713             803            698      False  20230619 11:31:33
       VP0P75_RTVDD_DPU5     757 mV        788       713             802            698      False  20230619 11:31:38
       VP0P75_RTVDD_DPU6     755 mV        788       713             803            698      False  20230619 11:31:42
       VP0P75_RTVDD_DPU7     753 mV        788       713             802            698      False  20230619 11:31:47
   VP0P82_AVDD_PCIE_DPU0     823 mV        861       779             877            763      False  20230619 11:31:18
   VP0P82_AVDD_PCIE_DPU1     823 mV        861       779             877            763      False  20230619 11:31:22
   VP0P82_AVDD_PCIE_DPU2     822 mV        861       779             877            763      False  20230619 11:31:27
   VP0P82_AVDD_PCIE_DPU3     822 mV        861       779             877            763      False  20230619 11:31:31
   VP0P82_AVDD_PCIE_DPU4     823 mV        861       779             877            763      False  20230619 11:31:36
   VP0P82_AVDD_PCIE_DPU5     820 mV        861       779             877            763      False  20230619 11:31:41
   VP0P82_AVDD_PCIE_DPU6     819 mV        861       779             877            763      False  20230619 11:31:45
   VP0P82_AVDD_PCIE_DPU7     824 mV        861       779             877            763      False  20230619 11:31:50
     VP0P85_VDD_MAC_DPU0     853 mV        893       808             910            791      False  20230619 11:31:14
     VP0P85_VDD_MAC_DPU1     854 mV        893       808             910            791      False  20230619 11:31:19
     VP0P85_VDD_MAC_DPU2     853 mV        893       808             910            791      False  20230619 11:31:23
     VP0P85_VDD_MAC_DPU3     856 mV        893       808             910            791      False  20230619 11:31:28
     VP0P85_VDD_MAC_DPU4     856 mV        893       808             910            791      False  20230619 11:31:33
     VP0P85_VDD_MAC_DPU5     856 mV        893       808             910            791      False  20230619 11:31:37
     VP0P85_VDD_MAC_DPU6     857 mV        893       808             910            791      False  20230619 11:31:42
     VP0P85_VDD_MAC_DPU7     852 mV        893       808             910            791      False  20230619 11:31:46
           VP1P0_PCH_CPU     870 mV        N/A       N/A            1242            562      False  20230619 11:31:54
         VP1P0_PCIE4_CPU    1000 mV       1070       930            1100            900      False  20230619 11:31:54
          VP1P2_DIMM_CPU    1200 mV       1284      1116            1320           1080      False  20230619 11:31:54
        VP1P2_TVDDH_DPU0    1205 mV       1260      1140            1284           1116      False  20230619 11:31:15
    VP1P2_TVDDH_DPU1_ADC    1214 mV       1268      1140            1284           1116      False  20230619 11:31:20
        VP1P2_TVDDH_DPU2    1211 mV       1260      1140            1284           1116      False  20230619 11:31:25
    VP1P2_TVDDH_DPU3_ADC    1210 mV       1268      1140            1284           1116      False  20230619 11:31:29
        VP1P2_TVDDH_DPU4    1211 mV       1260      1140            1284           1116      False  20230619 11:31:34
    VP1P2_TVDDH_DPU5_ADC    1209 mV       1268      1140            1284           1116      False  20230619 11:31:38
        VP1P2_TVDDH_DPU6    1215 mV       1260      1140            1284           1116      False  20230619 11:31:43
    VP1P2_TVDDH_DPU7_ADC    1210 mV       1268      1140            1284           1116      False  20230619 11:31:48
              VP1P05_CPU    1075 mV       1123       977            1155            945      False  20230619 11:31:54
      VP1P8_AOD_PLL_DPU0    1801 mV       1890      1710            1926           1674      False  20230619 11:31:14
      VP1P8_AOD_PLL_DPU1    1809 mV       1890      1710            1926           1674      False  20230619 11:31:18
      VP1P8_AOD_PLL_DPU2    1810 mV       1890      1710            1926           1674      False  20230619 11:31:23
      VP1P8_AOD_PLL_DPU3    1811 mV       1890      1710            1926           1674      False  20230619 11:31:28
      VP1P8_AOD_PLL_DPU4    1811 mV       1890      1710            1926           1674      False  20230619 11:31:32
      VP1P8_AOD_PLL_DPU5    1810 mV       1890      1710            1926           1674      False  20230619 11:31:37
      VP1P8_AOD_PLL_DPU6    1810 mV       1890      1710            1926           1674      False  20230619 11:31:42
      VP1P8_AOD_PLL_DPU7    1804 mV       1890      1710            1926           1674      False  20230619 11:31:46
        VP1P8_CPLD_SLED1    1800 mV       1890      1710            1926           1674      False  20230619 11:31:55
        VP1P8_CPLD_SLED2    1808 mV       1890      1710            1926           1674      False  20230619 11:31:58
        VP1P8_CPLD_SLED3    1805 mV       1890      1710            1926           1674      False  20230619 11:32:01
        VP1P8_CPLD_SLED4    1809 mV       1890      1710            1926           1674      False  20230619 11:31:04
               VP1P8_CPU    1800 mV       1962      1591            2016           1584      False  20230619 11:31:54
          VP1P8_NIC_DPU0    1803 mV       1890      1710            1926           1674      False  20230619 11:31:16
          VP1P8_NIC_DPU1    1812 mV       1890      1710            1926           1674      False  20230619 11:31:20
          VP1P8_NIC_DPU2    1797 mV       1890      1710            1926           1674      False  20230619 11:31:25
          VP1P8_NIC_DPU3    1810 mV       1890      1710            1926           1674      False  20230619 11:31:30
          VP1P8_NIC_DPU4    1804 mV       1890      1710            1926           1674      False  20230619 11:31:35
          VP1P8_NIC_DPU5    1802 mV       1890      1710            1926           1674      False  20230619 11:31:39
          VP1P8_NIC_DPU6    1808 mV       1890      1710            1926           1674      False  20230619 11:31:44
          VP1P8_NIC_DPU7    1811 mV       1890      1710            1926           1674      False  20230619 11:31:48
       VP1P8_SE_AOD_DPU0    1806 mV       1890      1710            1926           1674      False  20230619 11:31:13
       VP1P8_SE_AOD_DPU1    1811 mV       1890      1710            1926           1674      False  20230619 11:31:18
       VP1P8_SE_AOD_DPU2    1808 mV       1890      1710            1926           1674      False  20230619 11:31:23
       VP1P8_SE_AOD_DPU3    1809 mV       1890      1710            1926           1674      False  20230619 11:31:27
       VP1P8_SE_AOD_DPU4    1811 mV       1890      1710            1926           1674      False  20230619 11:31:32
       VP1P8_SE_AOD_DPU5    1813 mV       1890      1710            1926           1674      False  20230619 11:31:36
       VP1P8_SE_AOD_DPU6    1809 mV       1890      1710            1926           1674      False  20230619 11:31:41
       VP1P8_SE_AOD_DPU7    1806 mV       1890      1710            1926           1674      False  20230619 11:31:46
         VP1P8_VCCIN_CPU    1780 mV        N/A       N/A            2002           1478      False  20230619 11:31:54
     VP1P83_POD_PLL_DPU0    1799 mV       1922      1739            1959           1702      False  20230619 11:31:16
     VP1P83_POD_PLL_DPU1    1809 mV       1922      1739            1958           1702      False  20230619 11:31:21
     VP1P83_POD_PLL_DPU2    1804 mV       1922      1739            1959           1702      False  20230619 11:31:26
     VP1P83_POD_PLL_DPU3    1804 mV       1922      1739            1958           1702      False  20230619 11:31:30
     VP1P83_POD_PLL_DPU4    1808 mV       1922      1739            1959           1702      False  20230619 11:31:35
     VP1P83_POD_PLL_DPU5    1803 mV       1922      1739            1958           1702      False  20230619 11:31:39
     VP1P83_POD_PLL_DPU6    1807 mV       1922      1739            1959           1702      False  20230619 11:31:44
     VP1P83_POD_PLL_DPU7    1805 mV       1922      1739            1958           1702      False  20230619 11:31:49
      VP2P5_DDR_VPP_DPU0    2520 mV       2625      2375            2675           2325      False  20230619 11:31:17
      VP2P5_DDR_VPP_DPU1    2528 mV       2625      2375            2675           2325      False  20230619 11:31:21
      VP2P5_DDR_VPP_DPU2    2523 mV       2625      2375            2675           2325      False  20230619 11:31:26
      VP2P5_DDR_VPP_DPU3    2529 mV       2625      2375            2675           2325      False  20230619 11:31:30
      VP2P5_DDR_VPP_DPU4    2525 mV       2625      2375            2675           2325      False  20230619 11:31:35
      VP2P5_DDR_VPP_DPU5    2523 mV       2625      2375            2675           2325      False  20230619 11:31:40
      VP2P5_DDR_VPP_DPU6    2535 mV       2625      2375            2675           2325      False  20230619 11:31:45
      VP2P5_DDR_VPP_DPU7    2528 mV       2625      2375            2675           2325      False  20230619 11:31:49
          VP2P5_STBY_CPU    2519 mV       2725      2275            2750           2250      False  20230619 11:31:53
        VP3P3_CPLD_SLED1    3307 mV       3465      3135            3531           3069      False  20230619 11:31:54
        VP3P3_CPLD_SLED2    3325 mV       3465      3135            3531           3069      False  20230619 11:31:57
        VP3P3_CPLD_SLED3    3334 mV       3465      3135            3531           3069      False  20230619 11:32:00
        VP3P3_CPLD_SLED4    3327 mV       3465      3135            3531           3069      False  20230619 11:31:03
               VP3P3_CPU    3278 mV       3597      3003            3630           2970      False  20230619 11:31:11
          VP3P3_NIC_DPU0    3289 mV       3465      3135            3531           3069      False  20230619 11:31:55
      VP3P3_NIC_DPU1_ADC    3308 mV       3465      3135            3531           3069      False  20230619 11:31:56
          VP3P3_NIC_DPU2    3293 mV       3465      3135            3531           3069      False  20230619 11:31:58
      VP3P3_NIC_DPU3_ADC    3299 mV       3465      3135            3531           3069      False  20230619 11:31:59
          VP3P3_NIC_DPU4    3306 mV       3465      3135            3531           3069      False  20230619 11:32:01
      VP3P3_NIC_DPU5_ADC    3299 mV       3465      3135            3531           3069      False  20230619 11:31:02
          VP3P3_NIC_DPU6    3308 mV       3465      3135            3531           3069      False  20230619 11:31:04
      VP3P3_NIC_DPU7_ADC    3307 mV       3465      3135            3531           3069      False  20230619 11:31:05
          VP3P3_SATA_CPU    3302 mV       3597      3003            3630           2970      False  20230619 11:31:50
             VP3P3_SLED1    3301 mV       3465      3135            3531           3069      False  20230619 11:31:13
             VP3P3_SLED2    3303 mV       3465      3135            3531           3069      False  20230619 11:31:22
             VP3P3_SLED3    3318 mV       3465      3135            3531           3069      False  20230619 11:31:32
             VP3P3_SLED4    3322 mV       3465      3135            3531           3069      False  20230619 11:31:41
      VP3P3_STBY_BMC_CPU    3322 mV       3597      3003            3603           2970      False  20230619 11:31:52
          VP3P3_STBY_CPU    3322 mV       3597      3003            3603           2970      False  20230619 11:31:53
               VP5P0_CPU    5066 mV       5450      4550            5500           4500      False  20230619 11:31:11
             VP5P0_SLED1    4964 mV       5250      4750            5350           4650      False  20230619 11:31:18
             VP5P0_SLED2    4988 mV       5250      4750            5350           4650      False  20230619 11:31:27
             VP5P0_SLED3    5003 mV       5250      4750            5350           4650      False  20230619 11:31:36
             VP5P0_SLED4    5013 mV       5250      4750            5350           4650      False  20230619 11:31:46
root@sonic:/home/cisco# 

```
#### Pass/Fail Criteria
 * Verify warnings are all false.
 * Verify changing the threshold values (high, low, critical high and critical low) and check alarm warning changing into True
 * Verify changing back the threshold values to original one and check alarm warning changing into False


### 1.3 Check platform temperature

#### Steps
 * Use command `show platform temperature` to get platform temperature

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:

root@sonic:~#show platform temperature

         Sensor    Temperature    High TH    Low TH    Crit High TH    Crit Low TH    Warning          Timestamp
---------------  -------------  ---------  --------  --------------  -------------  ---------  -----------------
        DPU_0_T         37.438      100.0      -5.0           105.0          -10.0      False  20230728 06:39:18
        DPU_1_T         37.563      100.0      -5.0           105.0          -10.0      False  20230728 06:39:18
        DPU_2_T           38.5      100.0      -5.0           105.0          -10.0      False  20230728 06:39:18
        DPU_3_T         38.813      100.0      -5.0           105.0          -10.0      False  20230728 06:39:18
     FAN_Sensor         23.201      100.0      -5.0           102.0          -10.0      False  20230728 06:39:18
 MB_PORT_Sensor         21.813       97.0      -5.0           102.0          -10.0      False  20230728 06:39:18
MB_TMP421_Local          26.25      135.0      -5.0           140.0          -10.0      False  20230728 06:39:18
       SSD_Temp           40.0       80.0      -5.0            83.0          -10.0      False  20230728 06:39:18
   X86_CORE_0_T           37.0      100.0      -5.0           105.0          -10.0      False  20230728 06:39:18
   X86_PKG_TEMP           41.0      100.0      -5.0           105.0          -10.0      False  20230728 06:39:18
```
#### Pass/Fail Criteria
 * Verify warnings are all false
 * Verify changing the threshold values (high, low, critical high and critical low) and check alarm warning changing into True
 * Verify changing back the threshold values to original one and check alarm warning changing into False


### 1.4 Check DPU Console

#### Steps
 * Use serial port utility to access console for given DPU.
 * Get the mapping of serial port to DPU number from platform.json file. 
 * Get the number of DPU modules from PMON APIs - get_num_modules(). Test is to check for console access for all DPUs.

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: (shows connection to dpu-4 console and offset is 4 for this case)

root@sonic:/home/cisco# cat /proc/tty/driver/serial 
serinfo:1.0 driver revision:
0: uart:16550A port:000003F8 irq:16 tx:286846 rx:6096 oe:1 RTS|DTR|DSR|CD|RI
1: uart:16550A port:00006000 irq:19 tx:0 rx:0 CTS|DSR|CD
2: uart:16550A port:000003E8 irq:18 tx:0 rx:0 DSR|CD|RI
3: uart:16550A port:00007000 irq:16 tx:0 rx:0 CTS|DSR|CD
**4: uart:16550 mmio:0x94040040 irq:94 tx:0 rx:0
5: uart:16550 mmio:0x94040060 irq:94 tx:20 rx:68
6: uart:16550 mmio:0x94040080 irq:94 tx:0 rx:0
7: uart:16550 mmio:0x940400A0 irq:94 tx:0 rx:0
8: uart:16550 mmio:0x940400C0 irq:94 tx:0 rx:0
9: uart:16550 mmio:0x940400E0 irq:94 tx:0 rx:0
10: uart:16550 mmio:0x94040100 irq:94 tx:0 rx:0
11: uart:16550 mmio:0x94040120 irq:94 tx:0 rx:0**
12: uart:16550 mmio:0x94040140 irq:94 tx:0 rx:0 CTS|DSR
13: uart:16550 mmio:0x94040160 irq:94 tx:0 rx:0 CTS|DSR
14: uart:16550 mmio:0x94040180 irq:94 tx:0 rx:0 CTS|DSR
15: uart:16550 mmio:0x940401A0 irq:94 tx:0 rx:0 CTS|DSR

root@sonic:/home/cisco# /usr/bin/picocom -b 115200 /dev/ttyS8
picocom v3.1

port is        : /dev/ttyS8
flowcontrol    : none
baudrate is    : 115200
parity is      : none
databits are   : 8
stopbits are   : 1
escape is      : C-a
local echo is  : no
noinit is      : no
noreset is     : no
hangup is      : no
nolock is      : no
send_cmd is    : sz -vv
receive_cmd is : rz -vv -E
imap is        : 
omap is        : 
emap is        : crcrlf,delbs,
logfile is     : none
initstring     : none
exit_after is  : not set
exit is        : no

Type [C-a] [C-h] to see available commands
Terminal ready

sonic login: admin
Password: 
Linux sonic 6.1.0-11-2-arm64 #1 SMP Debian 6.1.38-4 (2023-08-08) aarch64
You are on
  ____   ___  _   _ _  ____
 / ___| / _ \| \ | (_)/ ___|
 \___ \| | | |  \| | | |
  ___) | |_| | |\  | | |___
 |____/ \___/|_| \_|_|\____|

-- Software for Open Networking in the Cloud --

Unauthorized access and/or use are prohibited.
All access and/or use are subject to monitoring.

Help:    https://sonic-net.github.io/SONiC/

Last login: Fri Jan 26 21:49:12 UTC 2024 from 169.254.143.2 on pts/1
admin@sonic:~$ 
admin@sonic:~$ 
Terminating...
Thanks for using picocom
root@sonic:/home/cisco#

```
#### Pass/Fail Criteria
 * Verify Login access is displayed.
 * cntrl+a and then cntrl+x to come out of the DPU console.


### 1.5 Check midplane ip address between NPU and DPU 

#### Steps 
 * Get the number of DPU modules from PMON APIs - get_num_modules()
 * Get mid plane ip address for each DPU module from PMON APIs - get_midplane_ip()

#### Verify in
 * Switch

#### Sample Output
```
    On Switch:

      root@sonic:/home/cisco# show ip interface
      Interface     Master    IPv4 address/mask    Admin/Oper    BGP Neighbor    Neighbor IP
      ------------  --------  -------------------  ------------  --------------  -------------
      eth0                    172.25.42.65/24      up/up         N/A             N/A
      eth1                    169.254.200.1/24      up/up         N/A             N/A
      eth2                    169.254.200.2/24      up/up         N/A             N/A
      eth3                    169.254.200.3/24      up/up         N/A             N/A
      eth4                    169.254.200.4/24      up/up         N/A             N/A
      eth5                    169.254.200.5/24     up/up         N/A             N/A
      eth6                    169.254.200.6/24     up/up         N/A             N/A
      eth7                    169.254.200.7/24     up/up         N/A             N/A
      eth8                    169.254.200.8/24     up/up         N/A             N/A
      lo                      127.0.0.1/16         up/up         N/A             N/A
      root@sonic:/home/cisco# 
```
#### Pass/Fail Criteria
 * Verify Ping works to all the mid plane ip listed in the api output

   
### 1.6 Check DPU shutdown and power up individually

#### Steps
 * Get the number of DPU modules from PMON APIs - get_num_modules()
 * Use command `config chassis modules shutdown <DPU_Number>` to shut down individual DPU
 * Use command `show chassis modules status` to show DPU status
 * Use command `config chassis modules startup <DPU_Number>` to power up individual DPU
 * Use command `show chassis modules status` to show DPU status

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:

root@sonic:/home/cisco# config chassis modules shutdown DPU4
root@sonic:/home/cisco#
root@sonic:/home/cisco# show chassis modules status
  Name    Description    Physical-Slot    Oper-Status    Admin-Status    Serial
------  -------------  ---------------  -------------  --------------  --------
  DPU0            N/A               -1         Online              up       N/A
  DPU1            N/A               -1         Online              up       N/A
  DPU2            N/A               -1         Online              up       N/A
  DPU3            N/A               -1         Online              up       N/A
  DPU4            N/A               -1        Offline            down       N/A
  DPU5            N/A               -1         Online              up       N/A
  DPU6            N/A               -1         Online              up       N/A
  DPU7            N/A               -1         Online              up       N/A

root@sonic:/home/cisco# config chassis modules startup DPU4
root@sonic:/home/cisco# show chassis modules status
  Name    Description    Physical-Slot    Oper-Status    Admin-Status    Serial
------  -------------  ---------------  -------------  --------------  --------
  DPU0            N/A               -1         Online              up       N/A
  DPU1            N/A               -1         Online              up       N/A
  DPU2            N/A               -1         Online              up       N/A
  DPU3            N/A               -1         Online              up       N/A
  DPU4            N/A               -1         Online              up       N/A
  DPU5            N/A               -1         Online              up       N/A
  DPU6            N/A               -1         Online              up       N/A
  DPU7            N/A               -1         Online              up       N/A


```
#### Pass/Fail Criteria
 * Verify DPU offline in show chassis modules status after DPU shut down
 * Verify DPU is shown in show chassis modules status after DPU powered on


### 1.7 Check removal of pcie link between NPU and DPU

#### Steps
 * Use command `pcieutil generate` to generate pcie yaml
 * Use `show platform pcieinfo -c` to run the pcie info test to check everything is passing
 * Use command `config chassis modules shutdown DPU<DPU_NUM>` to bring down the dpu (This will bring down the pcie link between npu and dpu)
 * Use `show platform pcieinfo -c` to run the pcie info test to check pcie link has been removed
 * Use command `config chassis modules startup DPU<DPU_NUM>` to bring up the dpu (This will rescan pcie links)
 * Use `show platform pcieinfo -c` to run the pcie info test to check everything is passing
 * This test is to check the PCie hot plug functinality since there is no OIR possible

#### Verify in
 * Switch
   
#### Sample Output
```
On Switch: Showing example of one DPU pcie link

root@sonic:/home/cisco# pcieutil generate
Are you sure to overwrite config file pcie.yaml with current pcie device info? [y/N]: y
Generated config file '/usr/share/sonic/device/x86_64-8102_28fh_dpu_o-r0/pcie.yaml'
root@sonic:/home/cisco# show platform pcieinfo -c

root@sonic:/home/cisco# echo 1 > /sys/bus/pci/devices/0000:1a:00.0/remove
root@sonic:/home/cisco# 
root@sonic:/home/cisco# echo 1 > /sys/bus/pci/rescan
root@sonic:/home/cisco# 
root@sonic:/home/cisco# show platform pcieinfo -c

```
#### Pass/Fail Criteria
 * Verify after removing pcie link, pcie info test fail only for that pcie link.
 * Verify pcieinfo test pass for all after bringing back up the link


### 1.8 Check the NTP date and timezone between DPU and NPU

#### Steps
 * Use command `date` to get date and time zone on Switch
 * Use command `ssh admin@169.254.x.x` to enter into required dpu.
 * Use command `date` to get date and time zone on DPU
   
#### Verify in
 * Switch and DPU
   
#### Sample Output
```
On Switch:

root@sonic:/home/cisco# date
Tue 23 Apr 2024 11:46:47 PM UTC
root@sonic:/home/cisco#
.
root@sonic:/home/cisco# ssh admin@169.254.200.1
root@sonic:/home/cisco#
.
On DPU:
root@sonic:/home/admin# date
Tue 23 Apr 2024 11:46:54 PM UTC
root@sonic:/home/cisco#

```
#### Pass/Fail Criteria
 * Verify both the date and time zone are same
 * Verify the syslogs on both switch and DPU to be same
 * Verify by changing time intentionally in DPU and restart the DPU. Verify again for time sync


### 1.9 Check the State of DPUs

#### Steps
 * Use command `show system-health DPU all` to get DPU health status. 
   
#### Verify in
 * Switch and DPU
   
#### Sample Output
```
On Switch:

root@sonic:~#show system-health DPU all  
            
Name       ID    Oper-Status          State-Detail                   State-Value     Time                               Reason                        
DPU0       1     Online               dpu_midplane_link_state        up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_booted_state               up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_control_plane_state        up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_data_plane_state           up              Wed 20 Oct 2023 06:52:28 PM UTC    


DPU1       2     Online               dpu_midplane_link_state        up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_booted_state               up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_control_plane_state        up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_data_plane_state           up            Wed 20 Oct 2023 06:52:28 PM UTC    

root@sonic:~#show system-health DPU 0
 
Name       ID    Oper-Status          State-Detail                   State-Value     Time                               Reason
DPU0       1     Offline              dpu_midplane_link_state        down            Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_booted_state               down            Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_control_plane_state        down            Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_data_plane_state           down            Wed 20 Oct 2023 06:52:28 PM UTC    
                                      
root@sonic:~#show system-health DPU 0
 
Name       ID    Oper-Status          State-Detail                   State-Value     Time                               Reason
DPU0       1     Partial Online       dpu_midplane_link_state        up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_booted_state               up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_control_plane_state        up              Wed 20 Oct 2023 06:52:28 PM UTC
                                      dpu_data_plane_state           down            Wed 20 Oct 2023 06:52:28 PM UTC    Pipeline failure


```
#### Pass/Fail Criteria
 * Verify the following criteria for Pass/Fail:
 * Online : All states are up
 * Offline: dpu_midplane_link_state or dpu_booted_state is down
 * Partial Online: dpu_midplane_link_state is up and dpu_booted_state is up and dpu_control_plane_state is up and dpu_data_plane_state is down
 * Verify powering down DPU and check for status and powering up again to check the status to show online. 


### 1.10 Check the Health of DPUs

####NOTE
 * This Test case is to be covered in Phase 2

#### Steps
 *  Use command `show system-health detail <DPU_SLOT_NUMBER>` to check the health of the DPU.
 
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:

root@sonic:/home/cisco# show system-health detail <DPU_SLOT_NUMBER>

Device: DPU0

System status summary

  System status LED  green
  Services:
    Status: Not OK
    Not Running: container_checker, lldp
  Hardware:
    Status: OK

system services and devices monitor list

Name                       Status    Type
-------------------------  --------  ----------
mtvr-r740-04-bf3-sonic-01  OK        System
rsyslog                    OK        Process

```
#### Pass/Fail Criteria 
 * Verify System Status - Green, Service Status - OK, Hardware Status - OK
 * Stop any docker in DPU and check for Service Status - Not OK and that docker as Not running
 * Start the docker again and Verify System Status - Green, Service Status - OK, Hardware Status - OK


### 1.11 Check reboot cause history

#### Steps
 *  The "show reboot-cause" CLI on the switch shows the most recent rebooted device, time and the cause. 
 *  The "show reboot-cause history" CLI on the switch shows the history of the Switch and all DPUs
 *  The "show reboot-cause history module-name" CLI on the switch shows the history of the specified module
 *  Use `config chassis modules shutdown <DPU_Number>` 
 *  Use `config chassis modules startup <DPU_Number>`
 *  Wait for 5 minutes for Pmon to update the DPU states
 *  Use `show reboot-cause <DPU_Number>` to check the latest reboot is displayed 
   
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:

root@sonic:~#show reboot-cause

Device          Name                    Cause                       Time                                User    Comment

switch          2023_10_20_18_52_28     Watchdog:1 expired;         Wed 20 Oct 2023 06:52:28 PM UTC     N/A     N/A
DPU3            2023_10_03_18_23_46     Watchdog: stage 1 expired;  Mon 03 Oct 2023 06:23:46 PM UTC     N/A     N/A
DPU2            2023_10_02_17_20_46     reboot                      Sun 02 Oct 2023 05:20:46 PM UTC     admin   User issued 'reboot'

root@sonic:~#show reboot-cause history

Device          Name                    Cause                       Time                                User    Comment

switch          2023_10_20_18_52_28     Watchdog:1 expired;         Wed 20 Oct 2023 06:52:28 PM UTC     N/A     N/A
switch          2023_10_05_18_23_46     reboot                      Wed 05 Oct 2023 06:23:46 PM UTC     user    N/A
DPU3            2023_10_03_18_23_46     Watchdog: stage 1 expired;  Mon 03 Oct 2023 06:23:46 PM UTC     N/A     N/A
DPU3            2023_10_02_18_23_46     Host Power-cycle            Sun 02 Oct 2023 06:23:46 PM UTC     N/A     Host lost DPU
DPU3            2023_10_02_17_23_46     Host Reset DPU              Sun 02 Oct 2023 05:23:46 PM UTC     N/A     N/A
DPU2            2023_10_02_17_20_46     reboot                      Sun 02 Oct 2023 05:20:46 PM UTC     admin   User issued 'reboot'

"show reboot-cause history module-name"

root@sonic:~#show reboot-cause history dpu3

Device      Name                    Cause                           Time                                User    Comment 
   
DPU3        2023_10_03_18_23_46     Watchdog: stage 1 expired;      Mon 03 Oct 2023 06:23:46 PM UTC     N/A     N/A
DPU3        2023_10_02_18_23_46     Host Power-cycle                Sun 02 Oct 2023 06:23:46 PM UTC     N/A     Host lost DPU
DPU3        2023_10_02_17_23_46     Host Reset DPU                  Sun 02 Oct 2023 05:23:46 PM UTC     N/A     N/A
```

#### Pass/Fail Criteria 
 * Verify the output to check the latest reboot cause with the date time stamp at the start of reboot
 * Verify all the reboot causes - Watchdog, reboot command, Host Reset


### 1.12 Check the DPU state after OS reboot

#### Steps

Existing Test case for NPU:
   * Reboot using a particular command (sonic reboot, watchdog reboot, etc)
   * All the timeout and poll timings are read from platform.json
   * Wait for ssh to drop
   * Wait for ssh to connect
   * Database check 
   * Check for uptime – (NTP sync)
   * Check for critical process 
   * Check for transceiver status
   * Check for pmon status
   * Check for reboot cause 
   * Reboot is successful
   
Reboot Test Case for DPU:
 * Save the configurations of all DPU state before reboot
 * Power on all the DPUs that were powered on before reboot using `config chassis modules startup <DPU_Number>`
 * Wait for DPUs to be up
 * Use command `show chassis modules status` to get DPU status
 * Get the number of DPU modules from PMON APIs - get_num_modules()
   
#### Verify in
 * Switch
   
#### Sample Output
```
On Switch:

root@sonic:/home/cisco# reboot
root@sonic:/home/cisco#
root@sonic:/home/cisco# config chassis modules startup <DPU_Number>
root@sonic:/home/cisco#
root@sonic:/home/cisco#
root@sonic:/home/cisco# show chassis modules status
  Name    Description    Physical-Slot    Oper-Status    Admin-Status    Serial
------  -------------  ---------------  -------------  --------------  --------
  DPU0            N/A               -1         Online              up       N/A
  DPU1            N/A               -1         Online              up       N/A
  DPU2            N/A               -1         Online              up       N/A
  DPU3            N/A               -1         Online              up       N/A
  DPU4            N/A               -1         Online              up       N/A
  DPU5            N/A               -1         Online              up       N/A
  DPU6            N/A               -1         Online              up       N/A
  DPU7            N/A               -1         Online              up       N/A
```

#### Pass/Fail Criteria 
 *  Verify number of DPUs from api and number of DPUs shown in the cli output.


## Objectives of API Test Cases

|    | **Test Case**   | **Intention**                              | **Comments** |
| ---------- | ---------- | ---------------------------------------- | ---------- |
| 1.1 | Check SmartSwitch specific ChassisClass APIs      | To verify the newly implemented SmartSwitch specific ChassisClass APIs | |
| 1.2 | Check modified ChassisClass APIs for SmartSwitch       |  To verify the existing ChassisClass APIs that undergo minor changes with the addition of SmartSwitch| |
| 1.3 | Check DpuModule APIs for SmartSwitch       |  To verify the newly implemented  DpuModule APIs for SmartSwitch| |
| 1.4 | Check modified ModuleClass APIs for SmartSwitch       |  To verify the existing ModuleClass APIs that undergo minor changes with the addition of SmartSwitch| 

## API Test Cases 

### 1.1 Check SmartSwitch specific ChassisClass APIs

#### Steps
 * Execute the following APIs on SmartSwitch
 * get_dpu_id(self, name):
    * Provide name (Example: DPU0 - Get it from platform.json file)
    * This API should return an integer from 0-7 (check it against platform.json)
 * is_smartswitch(self):
    * This API should return True
 * get_module_dpu_data_port(self, index):
    * It will return a dict as shown below.


#### Verify in
 * Switch

#### Sample Output
```
On Switch:
    get_dpu_id(self, DPU3)
    Output: 4
    is_smartswitch(self):
    Output: True
    get_module_dpu_data_port(self, DPU0):
    Output: {
                "interface": {"Ethernet224": "Ethernet0"}
            }
```
#### Pass/Fail Criteria
 *  The test result is a pass if the return value matches the expected value as shown in the "steps" and "Sample Output".


### 1.2 Check modified ChassisClass APIs for SmartSwitch

#### Steps
 * is_modular_chassis(self):
    * Should return False
 * get_num_modules(self):
    * Should return number of DPUs
 * get_module(self, index):
    * Make sure for each index this API returns an object and has some content and not None
    * Check that the object's class is inherited from the ModuleBase class
 * get_all_modules(self):
    * This should return a list of items
 * get_module_index(self, module_name):
    * Given the module name say “DPU0” should return the index of it “1”


#### Verify in
 * Switch

#### Sample Output
```
On Switch:
    is_modular_chassis(self):
    Output: False
    get_num_modules(self):
    Output: number of DPUs
    get_module(self, DPU0):
    Output: DPU0 object
    get_all_modules(self):
    Output: list of objects (one per DPU + 1 switch object)
    get_module_index(self, DPU0):
    Output: could be any value from 0 to modules count -1
```
#### Pass/Fail Criteria
 * The test result is a pass if the return value matches the expected value as shown in the "steps" and "Sample Output"


### 1.3 Check DpuModule APIs for SmartSwitch

#### Steps
 * get_dpu_id(self):
    * Should return ID of the DpuModule Ex: 1 on DPU0
* get_reboot_cause(self):
    * Reboot the module and then execute the "show reboot-cause ..." CLIs
    * Verify the output string shows the correct Time and Cause
    * Limit the testing to software reboot
 * get_state_info(self):
    * This should return an object
    * Stop one of the DPU containers on this DPU
    * Execute the CLI and check the dpu-control-plane value should be down
    * Check the complete list of containers without which the control plane can be up.
    * This test case can be extended to verify the DPU transition through all states.
 * get_health_info(self):
    * This should return an object
    * Stop one of the DPU containers on this DPU
    * Execute the CLI and check if the health shows the stopped container

#### Verify in
 * Switch

#### Sample Output
```
On Switch:
    get_dpu_id(self):
    Output: When on module DPUx should return x+1
    get_reboot_cause(self):
    Output: {"Device": "DPU0", "Name": 2024_05_31_00_33_30, "Cause":  "reboot", "Time": "Fri 31 May 2024 12:29:34 AM UTC", "User": "NA", "Comment": "NA"}
    get_state_info(self):
    Output: dpu state info object
    get_health_info(self):
    Output: dpu health info object
```
#### Pass/Fail Criteria
 * Verify that all the APIs mentioned return the expected output

 ### 1.4 Check modified ModuleClass APIs

#### Steps
 * get_base_mac(self):
    * Should return the base mac address of this DPU
    * Read all DPUs mac and verify if they are unique and not None
 * get_system_eeprom_info(self):
    * Verify the returned dictionary key:value
 * get_name(self):
    * Verify if this API returns “DPUx" on each of them
 * get_description(self):
    * Should return a string
 * get_type(self):
    * Should return “DPU” which is “MODULE_TYPE_DPU”
 * get_oper_status(self):
    * Should return the operational status of the DPU
    * Stop one ore more containers
    * Execute the CLI and see if it is down
    * Power down the dpu and check if the operational status is down.
 * reboot(self, reboot_type):
    * Issue this CLI with input “
    * verify if the module reboots
    * The reboot type should be updated based on SmartSwitch reboot HLD sonic-net/SONiC#1699
 * get_midplane_ip(self):
    * should return the midplane IP

#### Verify in
 * Switch

#### Sample Output
```
On Switch:
    get_base_mac(self):
    Output: BA:CE:AD:D0:D0:01
    get_system_eeprom_info(self):
    Output: eeprom info object
    get_name(self):
    Output: DPU2
    get_description(self):
    Output "Pensando DSC"
    get_type(self):
    Output: DPU
    get_oper_status(self):
    Output: Online
    reboot(self, reboot_type):
    Result: the DPU should reboot
    get_midplane_ip(self):
    Output: 169.254.200.1
```
#### Pass/Fail Criteria
 *  The test result is a pass if the return value matches the expected value as shown in the "steps" and "Sample Output".
