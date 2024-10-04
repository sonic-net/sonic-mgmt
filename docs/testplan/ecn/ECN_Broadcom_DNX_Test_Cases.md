
### ECN testcases for Broadcom-DNX platform
- [Existing testcase](#existing-testcase) 
- [New Approach](#new-approach)
- [Broadcom-DNX behavior](#broadcom-dnx-behavior)
- [Test case verification](#test-case-verification)


Revision of the document:

|  Revision  |    Date     |   Author    |   Change Description   |
|:----------:|:-----------:|:-----------:|:----------------------:|
|     01     | 10/01/2024  | Amit Pawar  |      First Draft       |

Overview
The testcase is applicable ONLY for Broadcom-DNX platforms and hence will be skipped for other platforms. The current testcase has a narrow range between Kmin and Kmax, making it challenging to verify the ECN marking probability. Furthermore, the Broadcom-DNX architecture results in slightly different behavior, as described below.

#### Existing testcase:

The ECN-dequeue test-case has Kmin, Kmax and Pmax set to 50000 bytes, 51000 bytes and 100% respectively. The packet-size is set to 1024B. Test involved sending 100 packets and ensuring that  first packet is ECN-marked and last packet is not ECN-marked.

However testing, with Broadcom-DNX platform, showed many issues with this approach. Setting of Kmin, Kmax and packet-size to 50000 bytes, 51000 bytes and 1024B respectively, meant that Kmin and Kmax were effectively set to around 50 and 51 packets, leaving window of just 1 packet. There is no verification to check the probability of the packets marked (as per Pmax) due to such a short window of Kmin and Kmax.

#### New Approach:

1. New ECN testcase for Broadcom-DNX platform sets Kmin and Kmax values to 800000 and 2000000 bytes respectively. With packet-size of 1024B, Kmin and Kmax translates to around 800 and 2000 packets.
2. The Pmax value is parameterized to different values, example - 5, 25, 50 and 75 to check probability of packets marked as congested between Kmin and Kmax values.
3. The packet-count is parameterized to different values, example - 800, 1600, 2400 and 4000 packets of 1024B each. Purpose is to have packet count less than Kmin (800), between Kmin and Kmax (1600), slightly above Kmax value (2400) and twice the value of Kmax (4000).

#### Broadcom-DNX behavior:

There are three aspects associated with Broadcom-DNX behavior for ECN-marking of the packets:
1. **ECN-marking on De-queue:**

    The packets are marked ECN upon the de-queue, so initial packets below the Kmin will also be ECN marked if the total number of packets are greater than Kmin value.
2. **Egress credits:**

   Even though there is congestion the egress side, the egress interface/asic assigns few credits to the ingress. These credits cause few packets to stay with egress queue and hence never ECN-marked. Typically, these packets range between 250-270 and 750-800 for 100 and 400Gbps interfaces respectively.
3. **Packets transferred to DRAM:**

    DNX platform enqueues the packets in the ingress asic’s VOQ until it gets the credit from egress asic. The VOQ consist of SRAM and DRAM buffers and it starts enqueuing in the SRAM buffer and once the SRAM buffer becomes scarce, packets are moved from SRAM to DRAM from the VOQ which are congested.  Multiple packets from same VOQ are dequeued from  SRAM and packed as 1 DRAM bundle and moved to DRAM. When ECN is marked, all the packets in that DRAM bundle are marked.
    


#### Test case verification:
1. With packet-count less than Kmin (800 packets), NONE of the packets should be marked as ECN. 
2. With packet count between Kmin and Kmx (1600), packets between 800-1600 packets should be check for ECN-marking probability (Pmax).
3. With packet count slightly above Kmax(2400), packets between Kmin and Kmax should be checked for ECN marking probability (Pmax).
4. With packet count above Kmax (4000), all the packets from 267-4000 should be marked as ECN. This will be around 760-4000 for 400Gbps interface.











        