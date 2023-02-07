package eu.cdinvest.jwtcheck;

import java.util.Date;
import java.util.Properties;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.io.IOException;

public class JwtLogger {

    private static String logfile = null;

    public static void add(String text) {

        try (InputStream input = new FileInputStream("config.properties")) {
            Properties prop = new Properties();
            prop.load(input);
            String logdir = prop.getProperty("logdir");

            if (logdir == null)
                return;

            File dir = new File(logdir);
            if (!dir.exists())
                dir.mkdirs();

            SimpleDateFormat logsf = new SimpleDateFormat("yyyy-MM-dd");
            String logfilename = logsf.format(new Date()) + ".log";

            Path logfile = Paths.get(logdir).resolve(Paths.get(logfilename));

            SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String timestamp = sf.format(new Date());

            try {
                FileWriter fw = new FileWriter(logfile.toString(), true);
                PrintWriter pw = new PrintWriter(fw);
                pw.append(timestamp + " - " + text + "\n");
                pw.close();
            } catch (IOException e) {
                return;
            }

        } catch (IOException e) {
            return;
        }

    }

}
