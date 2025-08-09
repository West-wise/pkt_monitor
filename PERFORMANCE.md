# Performance Measurement Guide for pkt_monitor

## 1. Overview

This guide provides a methodology for measuring the performance of the `pkt_monitor` application. The primary goal is to determine its maximum packet processing capacity and identify potential bottlenecks under various network conditions.

Performance testing is crucial for understanding how the application behaves under high load and for validating the impact of any code changes or optimizations.

## 2. Key Performance Metrics

The following metrics are essential for evaluating the performance of `pkt_monitor`:

*   **Packets Per Second (PPS):** The number of packets the application processes per second. This is a primary measure of packet processing throughput.
*   **Bits Per Second (BPS):** The amount of data (in bits) the application processes per second. This is a measure of network bandwidth throughput.
*   **Packet Drop Rate:** The number and percentage of packets that the application fails to process. This can be measured in two places:
    *   **Kernel/Interface Drops:** Reported by `pcap_stats` at the end of the run. These are packets dropped by the OS kernel or the network card before they even reach the application.
    *   **Application Drops:** Reported by `pkt_monitor`'s own statistics (`DROP` counter). These are packets that were successfully read by the application but were dropped internally (e.g., queue was full in live mode).
*   **CPU Usage:** The percentage of CPU time consumed by the `pkt_monitor` process and its threads. High CPU usage (approaching 100% on one or more cores) indicates a CPU bottleneck.
*   **Memory Usage:** The amount of RAM consumed by the application. This should be monitored to detect memory leaks and ensure efficient memory use.

## 3. Recommended Tools

*   **Traffic Generation:**
    *   **`iperf3`:** Excellent for generating high-volume TCP or UDP traffic to measure BPS.
    *   **`hping3` or `packETH`:** More advanced tools for crafting custom packets with specific sizes and rates, which is better for measuring PPS.
*   **System Monitoring:**
    *   **`htop`:** Provides a real-time, user-friendly view of CPU and memory usage per thread.
    *   **`vmstat`:** A command-line tool to report system-wide statistics like CPU context switches and interrupts.
*   **Profiling (Advanced):**
    *   **`perf`:** A powerful Linux profiling tool that can identify "hot spots" (functions where the most CPU time is spent) in the code.

## 4. Testing Methodology

A typical test setup involves two machines connected via a dedicated, high-speed network link (e.g., 10Gbps Ethernet) to avoid interference from other network traffic.

*   **Machine A (Sender):** Runs the traffic generation tool.
*   **Machine B (Receiver):** Runs the `pkt_monitor` application.

**Step-by-Step Guide:**

1.  **Prepare `pkt_monitor`:**
    *   On Machine B, compile the latest version of `pkt_monitor` in **release mode** (not debug mode) for maximum performance. You can do this by changing `CMAKE_BUILD_TYPE` in `CMakeLists.txt` from `Debug` to `Release` and removing the `-g -O0` flags.
    *   `set(CMAKE_BUILD_TYPE Release)`
    *   `set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")` (or similar optimization flags)

2.  **Start `pkt_monitor`:**
    *   On Machine B, start `pkt_monitor`, telling it to listen on the interface connected to Machine A. Use a number of threads that matches the number of available CPU cores.
    ```bash
    # Example with 4 worker threads on interface eth0
    ./build/project1_psh -i eth0 -t 4 -a build/top-1m.csv
    ```

3.  **Start System Monitoring:**
    *   On Machine B, in a separate terminal, start `htop` to monitor the `project1_psh` process.
    ```bash
    htop -p $(pgrep project1_psh)
    ```

4.  **Generate Traffic:**
    *   On Machine A, start your chosen traffic generator.
    *   **Example with `iperf3` (for BPS testing):**
        ```bash
        # On Machine B, start iperf3 server
        iperf3 -s
        # On Machine A, start iperf3 client, sending data to Machine B's IP
        iperf3 -c <IP_of_Machine_B> -t 60 -b 5G # Send 5 Gbps for 60 seconds
        ```
    *   **Example with `hping3` (for PPS testing):**
        ```bash
        # On Machine A, send small UDP packets as fast as possible
        sudo hping3 --udp -p 5001 --fast <IP_of_Machine_B>
        ```

5.  **Collect Results:**
    *   During the test, observe the real-time statistics printed by `pkt_monitor` every second. Note the PPS and BPS values.
    *   Observe `htop` to see if any of the threads (main capture thread or worker threads) are hitting 100% CPU.
    *   When the test is complete (or when you stop `pkt_monitor` with Ctrl+C), it will print a final report. Record the total packets, bytes, and drops.

## 5. Interpreting the Results

*   **CPU Bottleneck:** If one or more threads are consistently at or near 100% CPU, the application is CPU-bound.
    *   If the **main thread** is the bottleneck, the packet capture and distribution logic may be too slow.
    *   If the **worker threads** are the bottleneck, the packet processing logic (parsing, trie search) is the slow part.
    *   Use `perf` to dig deeper and find the exact functions causing the high CPU usage.
*   **No CPU Bottleneck, High Drop Rate:** If CPU usage is not at 100% but the drop rate is high (especially kernel drops), it could indicate a problem with the OS network stack tuning or a limitation of the `libpcap` buffer.
*   **Memory Growth:** If memory usage in `htop` continuously increases throughout the test, it may indicate a memory leak that was not caught in the review.

By incrementally increasing the traffic rate (e.g., from 1Gbps to 2Gbps, and so on), you can find the "breaking point" where the application can no longer keep up and starts dropping a significant number of packets. This point represents the application's maximum processing capacity.
