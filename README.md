# cybersecurity
#vulnerability scanner analysis
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VulnerabilityScanner {
    private static final int TIMEOUT = 100;  
    private static final int PORT_RANGE = 1024; 

    public static List<Integer> scanPorts(String target) {
        List<Integer> openPorts = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(10);

        for (int port = 1; port <= PORT_RANGE; port++) {
            final int currentPort = port;
            executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(target, currentPort), TIMEOUT);
                    synchronized (openPorts) {
                        openPorts.add(currentPort);
                    }
                } catch (Exception ignored) { }
            });
        }
        executor.shutdown();
        while (!executor.isTerminated()) { }
        return openPorts;
    }

    public static String checkSoftwareVersion(String target) {
        try {
            URI uri = new URI("https://" + target);
            HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            String server = connection.getHeaderField("Server");
            return (server != null) ? server : "Unknown";
        } catch (URISyntaxException | java.io.IOException e) {
            return "Unable to determine: " + e.getMessage();
        }
    }

    public static List<String> checkMisconfigurations(String target) {
        List<String> misconfigurations = new ArrayList<>();
        try {
            URI uri = new URI("http://" + target);
            HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            if (connection.getHeaderField("X-Frame-Options") == null) {
                misconfigurations.add("Missing X-Frame-Options header");
            }
            if (connection.getHeaderField("Strict-Transport-Security") == null) {
                misconfigurations.add("Missing HSTS header");
            }
            if (!"nosniff".equals(connection.getHeaderField("X-Content-Type-Options"))) {
                misconfigurations.add("Missing or incorrect X-Content-Type-Options header");
            }
            if (connection.getHeaderField("X-XSS-Protection") == null) {
                misconfigurations.add("Missing X-XSS-Protection header");
            }
            if (connection.getHeaderField("Content-Security-Policy") == null) {
                misconfigurations.add("Missing Content-Security-Policy header");
            }
            if (connection.getHeaderField("X-Permitted-Cross-Domain-Policies") == null) {
                misconfigurations.add("Missing X-Permitted-Cross-Domain-Policies header");
            }
        } catch (URISyntaxException | java.io.IOException e) {
            misconfigurations.add("Unable to check misconfigurations: " + e.getMessage());
        }
        return misconfigurations;
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java VulnerabilityScanner <target>");
            return;
        }

        String target = args[0];
        System.out.println("Scanning target: " + target);

        System.out.println("\nScanning for open ports...");
        List<Integer> openPorts = scanPorts(target);
        System.out.println("Open ports: " + openPorts);

        System.out.println("\nChecking software version...");
        String softwareVersion = checkSoftwareVersion(target);
        System.out.println("Server software: " + softwareVersion);

        System.out.println("\nChecking for misconfigurations...");
        List<String> misconfigurations = checkMisconfigurations(target);
        if (!misconfigurations.isEmpty()) {
            System.out.println("Misconfigurations found:");
            for (String misconfig : misconfigurations) {
                System.out.println("- " + misconfig);
            }
        } else {
            System.out.println("No misconfigurations detected");
        }
    }
}
