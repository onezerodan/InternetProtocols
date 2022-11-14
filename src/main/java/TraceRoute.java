import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TraceRoute {

    public static List<InetAddress> getAddresses(InetAddress address) {

        List<InetAddress> ipAddresses = new ArrayList<>();
        try {

            Process traceRt = Runtime.getRuntime().exec("traceroute " + address.getHostAddress());

            try (InputStream fis = traceRt.getInputStream();
                 InputStreamReader isr = new InputStreamReader(fis,
                         StandardCharsets.UTF_8);
                 BufferedReader br = new BufferedReader(isr)) {
                for (String line = br.readLine(); line != null && !line.contains("* * *"); line = br.readLine()) {
                    if (!line.contains("* * *")) {
                        ipAddresses.add(InetAddress.getByName(StringUtils.substringBetween(line, "(", ")")));
                    }
                    System.out.println(line);
                }
            }
            return ipAddresses;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    private static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    public static boolean checkIfIpIsPrivate(InetAddress inetAddress){

        String address = inetAddress.toString().replace("/", "");
        int[] addressParts = Arrays.stream(
                address.split("\\.")
            ).mapToInt(Integer::parseInt).toArray();

        // refer to RFC 1918
        // 10/8 prefix
        // 172.16/12 prefix
        // 192.168/16 prefix
        return (
                (addressParts[0] == 10)
                || ((addressParts[0] == 172) && (addressParts[1] == 16))
                || ((addressParts[0] == 192) && (addressParts[1] == 168))
                );
    }

    public static String getASNumber(InetAddress inetAddress) throws IOException {
        URL url = new URL("https://stat.ripe.net/data/related-prefixes/data.json?resource=" + inetAddress.getHostAddress());
        JSONObject json = new JSONObject(IOUtils.toString(url, StandardCharsets.UTF_8));
        String asNumber = "";

        try {
            asNumber = String.valueOf(json.getJSONObject("data").getJSONArray("prefixes").getJSONObject(0).getString("origin_asn"));
            if (asNumber.matches("\\d+")) return asNumber;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "Not Found";
        }


    public static void run(String addressToTrace) throws IOException {
        InetAddress inetAddress;
        try {
            inetAddress = InetAddress.getByName(addressToTrace);
        } catch (UnknownHostException e) {
            System.out.println("Wrong address");
            return;
        }

        List<List<String>> result = new ArrayList<>();
        int counter=1;
        for (InetAddress address : getAddresses(inetAddress)) {
            if (!checkIfIpIsPrivate(address)) {
                result.add(Arrays.asList(String.valueOf(counter), address.getHostAddress(), getASNumber(address)));
            }
            counter++;
        }

        String leftAlignFormat = "|%-4s | %-15s | %-15s |%n";

        System.out.format("+-----+-----------------+-----------------+%n");
        System.out.format("| №   | IP              | AS              |%n");
        System.out.format("+-----+-----------------+-----------------+%n");
        for (List<String> strings : result) {
            System.out.format(leftAlignFormat, strings.get(0), strings.get(1), strings.get(2));
        }
        System.out.format("+-----+-----------------+-----------------+%n");
    }

}



