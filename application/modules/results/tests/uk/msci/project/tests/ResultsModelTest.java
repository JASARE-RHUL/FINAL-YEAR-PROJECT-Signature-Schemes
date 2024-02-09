package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.ResultsModel;

public class ResultsModelTest {

  private ResultsModel resultsModel;
  private File testFile;



  @BeforeEach
  void setUp() {
    // Create a ResultsModel with some dummy data
    resultsModel = new ResultsModel(Arrays.asList(1000000L, 2000000L, 1500000L));
    resultsModel.calculateStatistics();
  }



  @Test
  void testExportStatisticsToCSV() throws IOException {
    resultsModel.exportStatisticsToCSV("resultsStats.csv");
    File testFile = new File(System.getProperty("user.dir"), "resultsStats.csv");

    assertTrue(testFile.exists());

    // Verify the contents of the file
    try (BufferedReader reader = new BufferedReader(
        new FileReader(MainTestUtility.getFile("resultsStats", ".csv").get()))) {
      List<String> expectedLines = Arrays.asList(
          "Statistic,Value",
          "Number of Trials," + resultsModel.getNumTrials(),
          "Overall Time," + String.format("%.2f ms", resultsModel.getOverallData()),
          "Mean," + String.format("%.2f ms", resultsModel.getMeanData()),
          "Confidence Interval," + String.format("%.2f ms - %.2f ms",
              resultsModel.getConfidenceInterval()[0], resultsModel.getConfidenceInterval()[1]),
          "25th Percentile," + String.format("%.2f ms", resultsModel.getPercentile25Data()),
          "Median," + String.format("%.2f ms", resultsModel.getMedianData()),
          "75th Percentile," + String.format("%.2f ms", resultsModel.getPercentile75Data()),
          "Range," + String.format("%.2f ms", resultsModel.getRangeData()),
          "Standard Deviation," + String.format("%.2f ms", resultsModel.getStdDeviationData()),
          "Variance," + String.format("%.2f ms", resultsModel.getVarianceData()),
          "Minimum Time," + String.format("%.2f ms", resultsModel.getMinTimeData()),
          "Maximum Time," + String.format("%.2f ms", resultsModel.getMaxTimeData())
      );
      for (String expectedLine : expectedLines) {
        assertEquals(expectedLine, reader.readLine());
      }
    }
    MainTestUtility.getFile("resultsStats", ".csv").get().delete();

  }


}
