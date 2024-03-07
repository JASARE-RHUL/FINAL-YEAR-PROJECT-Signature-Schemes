package uk.msci.project.rsa;

import java.awt.Color;
import java.awt.Font;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.control.Button;
import javafx.util.Pair;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.CategoryLabelPositions;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.SymbolAxis;
import org.jfree.chart.fx.ChartViewer;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.category.StackedBarRenderer;
import org.jfree.chart.renderer.xy.XYErrorRenderer;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.statistics.BoxAndWhiskerItem;
import org.jfree.data.statistics.DefaultBoxAndWhiskerCategoryDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.data.xy.YIntervalSeries;
import org.jfree.data.xy.YIntervalSeriesCollection;

/**
 * Manages the generation and display of graphical representations of benchmarking results in RSA
 * cryptography. This includes histograms, box plots, and line graphs for both individual key
 * analysis and comparative analysis across different key sizes and configurations. The GraphManager
 * supports a 'comparison mode' which allows benchmarking and comparing results between custom
 * parameter In this mode, users can compare the performance of different key sizes and
 * configurations side-by-side using a variety of graph types.
 */
public class GraphManager {

  /**
   * The total number of trials conducted in the benchmarking process.
   */
  private int totalTrials;


  /**
   * The total number of keys used in the benchmarking process.
   */
  private int totalKeys;
  /**
   * The number of rows used in comparison mode.
   */
  private int numRowsComparisonMode;
  /**
   * Number of key sizes selected for comparison mode. This indicates how many different key sizes
   * will be used to benchmark and compare provably secure versus standard parameters.
   */
  private int numKeySizesForComparisonMode;

  /**
   * Flag indicating whether the current results are from a signature operation.
   */
  private boolean isSignatureOperationResults;

  /**
   * The current key index being displayed in the results view.
   */
  private int keyIndex;
  /**
   * Stores the last selected graph button to maintain the active state across different result
   * sets.
   */
  private Button lastSelectedGraphButton;

  /**
   * Stores precomputed graph views to avoid re-rendering for each view request.
   */
  private Map<String, ChartViewer> precomputedGraphs;

  /**
   * Initializes a new GraphManager with specified parameters.
   *
   * @param totalTrials                  Number of trials conducted in benchmarking.
   * @param totalKeys                    Number of keys used in benchmarking.
   * @param numRowsComparisonMode        Number of rows for comparison mode.
   * @param numKeySizesForComparisonMode Number of key sizes selected for comparison mode.
   * @param isSignatureOperationResults  Flag indicating if results are from a signature operation.
   */
  public GraphManager(int totalTrials, int totalKeys, int numRowsComparisonMode,
      int numKeySizesForComparisonMode, boolean isSignatureOperationResults) {
    precomputedGraphs = new HashMap<String, ChartViewer>();
    this.totalTrials = totalTrials;
    this.totalKeys = totalKeys;
    this.numRowsComparisonMode = numRowsComparisonMode;
    this.numKeySizesForComparisonMode = numKeySizesForComparisonMode;
    this.isSignatureOperationResults = isSignatureOperationResults;

  }

  /**
   * Precomputes and stores graphs for all keys to optimise performance during graph switching.
   *
   * @param resultsModels A list of ResultsModel objects containing benchmarking data.
   * @param keyLengths    A list of integers representing key lengths.
   */
  void precomputeGraphs(List<ResultsModel> resultsModels, List<Integer> keyLengths) {
    for (int keyIndex = 0; keyIndex < totalKeys; keyIndex++) {
      int keyLength = keyLengths.get(keyIndex);
      // Precompute and store each type of graph for each key
      String histogramKey = "Histogram_" + keyIndex;
      precomputedGraphs.put(histogramKey,
          displayHistogramForKey(keyIndex, keyLength, resultsModels));

      String boxPlotKey = "BoxPlot_" + keyIndex;
      ChartViewer boxPlotViewer = displayBoxPlotForKey(keyIndex, keyLength, resultsModels);
      precomputedGraphs.put(boxPlotKey, boxPlotViewer);

    }
  }

  /**
   * Precomputes and stores graphs for comparison mode, facilitating quick switching between
   * graphs.
   *
   * @param resultsModels            A list of ResultsModel objects containing benchmarking data.
   * @param comparisonModeRowHeaders Headers for rows in comparison mode.
   * @param results                  A list of longs representing benchmarking results.
   * @param keyLengths               A list of integers representing key lengths.
   */
  void precomputeGraphsComparisonMode(List<ResultsModel> resultsModels,
      List<String> comparisonModeRowHeaders, List<Long> results, List<Integer> keyLengths) {
    for (int keySizeIndex = 0; keySizeIndex < numKeySizesForComparisonMode; keySizeIndex++) {
      int keyLength = ResultsUtility.getKeyLength(keySizeIndex, resultsModels,
          numKeySizesForComparisonMode, keyLengths);
      // Precompute and store each type of graph for each key
      String histogramKey = "Histogram_" + keySizeIndex;
      precomputedGraphs.put(histogramKey,
          displayStackedHistogram(keySizeIndex, keyLength, resultsModels, comparisonModeRowHeaders,
              results));

      String lineChartMeanKey = "LineChartMeanTimes_" + keySizeIndex;
      ChartViewer lineChartMeanViewer = displayLineGraphMeanForComparisonMode(keySizeIndex,
          keyLength, resultsModels, comparisonModeRowHeaders);
      precomputedGraphs.put(lineChartMeanKey, lineChartMeanViewer);

      String boxPlotKey = "BoxPlot_" + keySizeIndex;
      ChartViewer boxPlotViewer = displayBoxPlotForComparisonMode(keySizeIndex, keyLength,
          resultsModels, comparisonModeRowHeaders);
      precomputedGraphs.put(boxPlotKey, boxPlotViewer);

    }
  }

  /**
   * Calculates the bin width using the Freedman-Diaconis rule.
   *
   * @param results The results to use in the calculation.
   * @return The calculated bin width.
   */
  public static double calculateFreedmanDiaconisBinWidth(List<Long> results) {
    double q1 = BenchmarkingUtility.calculatePercentile(results, 0.25);
    double q3 = BenchmarkingUtility.calculatePercentile(results, 0.75);
    double iqr = (q3 - q1) / 1E6;
    return 2 * iqr * Math.pow(results.size(), -1 / 3.0);
  }

  /**
   * Calculates the number of bins for a histogram based on the given results.
   *
   * @param results The results to use in the calculation.
   * @return The number of bins.
   */
  public static int calculateNumberOfBins(List<Long> results) {
    double min = BenchmarkingUtility.getMin(results) / 1E6;
    double max = BenchmarkingUtility.getMax(results) / 1E6;
    return (int) Math.ceil((max - min) / calculateFreedmanDiaconisBinWidth(results));
  }

  /**
   * Creates a dataset for a stacked histogram specifically tailored to signature operations. This
   * dataset is generated based on the key size index provided and is intended for comparative
   * analysis in 'comparison mode'.
   *
   * @param keySizeIndex                 The index of the key size for which the dataset is
   *                                     prepared.
   * @param numKeySizesForComparisonMode Number of key sizes selected for comparison mode.
   * @param resultsModels                A list of ResultsModel objects containing benchmarking
   *                                     data.
   * @return A CategoryDataset suitable for creating a stacked histogram, reflecting the
   * distribution of results for different hash functions and key configurations.
   */
  public CategoryDataset createStackedHistogramDatasetSignatures(int keySizeIndex,
      int numKeySizesForComparisonMode, List<ResultsModel> resultsModels) {
    DefaultCategoryDataset dataset = new DefaultCategoryDataset();

    // Calculate the range of model indices for the specified key size
    int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int endModelIndex = (keySizeIndex + 1) * (resultsModels.size() / numKeySizesForComparisonMode);

    // Calculate minimum, bin width, and number of bins for all combined results
    List<Long> allCombinedResults = new ArrayList<>();
    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      allCombinedResults.addAll(resultsModels.get(modelIndex).getResults());
    }
    double min = BenchmarkingUtility.getMin(allCombinedResults) / 1E6;
    double binWidth = calculateFreedmanDiaconisBinWidth(allCombinedResults);
    int numBins = calculateNumberOfBins(allCombinedResults);

    // Initialize bin counts for each series
    Map<String, int[]> seriesBinCounts = new HashMap<>();

    // Iterate over each key and hash function combination
    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      ResultsModel model = resultsModels.get(modelIndex);

      // Retrieve the hash function for the current combination
      String hashFunctionName = model.getHashFunctionName();
      String keyConfigString = model.getConfigString();
      String seriesName =
          modelIndex + ". " + keyConfigString + " - " + hashFunctionName;

      double[] values = model.getResults().stream().mapToDouble(ns -> ns / 1_000_000.0).toArray();

      // Populate bin counts
      seriesBinCounts.putIfAbsent(seriesName, new int[numBins]);
      for (double value : values) {
        int bin = (int) ((value - min) / binWidth);
        bin = Math.min(Math.max(bin, 0), numBins - 1);
        seriesBinCounts.get(seriesName)[bin]++;
      }
    }

    // Add the bin counts to the dataset
    for (Map.Entry<String, int[]> entry : seriesBinCounts.entrySet()) {
      String seriesName = entry.getKey();
      int[] binCounts = entry.getValue();
      addBinCountDataset(dataset, min, binWidth, numBins, seriesName, binCounts);
    }

    return dataset;
  }


  /**
   * Creates a dataset for a general stacked histogram based on a given key index. This dataset is
   * used for generating histograms in comparison modes, providing a detailed view of the
   * benchmarking results.
   *
   * @param keyIndex                 The index of the key for which the dataset is prepared.
   * @param comparisonModeRowHeaders Headers for rows in comparison mode.
   * @param results                  A list of benchmarking results.
   * @param resultsModels            A list of ResultsModel objects containing benchmarking data.
   * @return A CategoryDataset suitable for creating a stacked histogram.
   */
  public CategoryDataset createStackedHistogramDataset(int keyIndex,
      List<String> comparisonModeRowHeaders, List<Long> results, List<ResultsModel> resultsModels) {

    // Create the dataset
    DefaultCategoryDataset dataset = new DefaultCategoryDataset();

    // Determine the combined range and bin width
    List<Long> combinedResults = results.subList(
        keyIndex * (this.totalTrials / totalKeys) * numRowsComparisonMode,
        (keyIndex * (this.totalTrials / totalKeys) * numRowsComparisonMode)
            + (this.totalTrials / totalKeys) * numRowsComparisonMode
    );
    double min = BenchmarkingUtility.getMin(combinedResults) / 1E6;
    double binWidth = calculateFreedmanDiaconisBinWidth(combinedResults);
    int numBins = calculateNumberOfBins(combinedResults);

    // Initialise bin counts for each series
    Map<String, int[]> seriesBinCounts = new HashMap<>();

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + numRowsComparisonMode;
        i++) {

      ResultsModel model = resultsModels.get(i);
      String seriesName = i + ". " + comparisonModeRowHeaders.get(i % numRowsComparisonMode);
      seriesBinCounts.putIfAbsent(seriesName, new int[numBins]);

      double[] values = model.getResults().stream()
          .mapToDouble(ns -> ns / 1_000_000.0) // Convert to milliseconds
          .toArray();

      // Populate bin counts
      for (double value : values) {
        int bin = (int) ((value - min) / binWidth);
        bin = Math.min(Math.max(bin, 0), numBins - 1); // Clamp to valid range
        seriesBinCounts.get(seriesName)[bin]++;
      }
    }

    // Add the bin counts to the dataset
    for (Map.Entry<String, int[]> entry : seriesBinCounts.entrySet()) {
      String seriesName = entry.getKey();
      int[] binCounts = entry.getValue();
      addBinCountDataset(dataset, min, binWidth, numBins, seriesName, binCounts);
    }

    return dataset;
  }


  /**
   * Prepares a histogram dataset for a specific key index, primarily used in non-comparison mode.
   * This method organizes data into appropriate bins for histogram representation.
   *
   * @param keyIndex      The index of the key for which the dataset is prepared.
   * @param resultsModels A list of ResultsModel objects containing benchmarking data.
   * @return A histogram dataset for the specified key.
   */
  private DefaultCategoryDataset prepareHistogramForKey(int keyIndex,
      List<ResultsModel> resultsModels) {
    DefaultCategoryDataset dataset = new DefaultCategoryDataset();
    ResultsModel model = resultsModels.get(keyIndex);

    double min = model.getMinTimeData() / 1_000_000.0; // convert to milliseconds
    double binWidth = calculateFreedmanDiaconisBinWidth(model.getResults());
    int numBins = calculateNumberOfBins(model.getResults());
    String seriesName = "Key " + (keyIndex + 1);
    int[] binCounts = new int[numBins]; // Array to hold the count of values in each bin

    double[] values = model.getResults().stream()
        .mapToDouble(ns -> ns / 1_000_000.0) // Convert to milliseconds
        .toArray();

    // Populate bin counts
    for (double value : values) {
      int bin = (int) ((value - min) / binWidth);
      bin = Math.min(Math.max(bin, 0), numBins - 1); // Clamp to valid range
      binCounts[bin]++; // Increment the count for the bin
    }

    // Add the bin counts to the dataset
    addBinCountDataset(dataset, min, binWidth, numBins, seriesName, binCounts);

    return dataset;
  }

  /**
   * Adds data for bin counts to the given category dataset. This method is used for preparing
   * datasets for histogram graphs by populating it with frequency data for specific value ranges
   * (bins).
   *
   * @param dataset    The category dataset to which the bin counts will be added.
   * @param min        The minimum value in the range of data.
   * @param binWidth   The width of each bin (value range).
   * @param numBins    The total number of bins.
   * @param seriesName The name of the series to which this bin data belongs.
   * @param binCounts  An array of integers representing the count of values in each bin.
   */
  private void addBinCountDataset(DefaultCategoryDataset dataset, double min, double binWidth,
      int numBins, String seriesName, int[] binCounts) {
    for (int bin = 0; bin < numBins; bin++) {
      double lowerBound = min + (bin * binWidth);
      double upperBound = lowerBound + binWidth;
      // Format the bin range as a label
      String binLabel = String.format("%.1f-%.1f ms", lowerBound, upperBound);
      dataset.addValue(binCounts[bin], seriesName,
          binLabel); // Add the count of the bin to the dataset
    }
  }


  /**
   * Creates a stacked histogram chart using the provided dataset.
   *
   * @param dataset The dataset to create the histogram from.
   * @param title   The title of the histogram chart.
   * @return A JFreeChart object representing the stacked histogram chart.
   */
  private JFreeChart createStackedHistogramChart(CategoryDataset dataset, String title) {
    // Create the stacked bar chart with the dataset
    JFreeChart chart = ChartFactory.createStackedBarChart(
        title,
        "Category",
        "Frequency",
        dataset,
        PlotOrientation.VERTICAL,
        true,                  // include legend
        true,                  // tooltips
        false
    );
    //chart should be rendered as a stacked bar chart, where
    // each category contains stacked bars representing different bins of data
    CategoryPlot plot = chart.getCategoryPlot();
    StackedBarRenderer renderer = new StackedBarRenderer();
    plot.setRenderer(renderer);

    for (int i = 0; i < dataset.getRowCount(); i++) {
      // generate colors based on the hue, saturation, and brightness.
      // Each series is assigned a different hue value based on its index.
      Color color = Color.getHSBColor((float) i / dataset.getRowCount(), 0.85f, 0.85f);
      renderer.setSeriesPaint(i, color);
    }

    // Set the category label positions to avoid overlap
    CategoryAxis domainAxis = plot.getDomainAxis();
    domainAxis.setCategoryLabelPositions(CategoryLabelPositions.UP_45);

    return chart;
  }

  /**
   * Creates a histogram from the given category dataset.
   *
   * @param dataset The dataset from which the histogram is to be created.
   * @param title   The title for the histogram chart.
   * @return A JFreeChart object representing the histogram.
   */
  private JFreeChart createHistogramFromDataset(CategoryDataset dataset, String title) {
    JFreeChart chart = ChartFactory.createStackedBarChart(
        title,
        "Time (ms)",
        "Frequency",
        dataset,
        PlotOrientation.VERTICAL,
        false,
        true,
        false
    );
    CategoryPlot plot = chart.getCategoryPlot();
    StackedBarRenderer renderer = new StackedBarRenderer();
    plot.setRenderer(renderer);

    // Set the category label positions to avoid overlap
    CategoryAxis domainAxis = plot.getDomainAxis();
    domainAxis.setCategoryLabelPositions(CategoryLabelPositions.UP_45);

    return chart;


  }

  /**
   * Creates a BoxAndWhiskerItem from the provided ResultsModel.
   *
   * @param model The model containing statistical data.
   * @return A BoxAndWhiskerItem representing the statistical data.
   */
  private BoxAndWhiskerItem createBoxAndWhiskerItem(ResultsModel model) {
    double mean = model.getMeanData();
    double median = model.getMedianData();
    double q1 = model.getPercentile25Data();
    double q3 = model.getPercentile75Data();
    double min = model.getMinTimeData();
    double max = model.getMaxTimeData();

    return new BoxAndWhiskerItem(
        mean,
        median,
        q1,
        q3,
        min,
        max,
        null, // Min outlier
        null,     // Max outlier
        null     // Outlier list
    );
  }

  /**
   * Prepares a dataset for a box plot corresponding to a specific key. This method aggregates
   * statistical data such as mean, median, quartiles, and outliers for visualizing the distribution
   * of benchmarking results.
   *
   * @param keyIndex      Index of the key for which the dataset is prepared.
   * @param resultsModels A list of ResultsModel objects containing benchmarking data.
   * @return A dataset ready for generating a box plot.
   */
  private DefaultBoxAndWhiskerCategoryDataset prepareBoxPlotDatasetForKey(int keyIndex,
      List<ResultsModel> resultsModels) {
    DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();
    ResultsModel model = resultsModels.get(keyIndex);

    dataset.add(createBoxAndWhiskerItem(model), "Key " + keyIndex + 1, "");
    return dataset;
  }

  /**
   * Prepares a dataset for box plots in comparison mode specifically for signature operations. It
   * collects statistical data from multiple ResultsModel instances, offering a detailed insight
   * into performance variations across different hash functions and key configurations.
   *
   * @param keySizeIndex  Index of the key size for which the dataset is prepared.
   * @param resultsModels A list of ResultsModel objects containing benchmarking data.
   * @return A dataset ready for generating a box plot in comparison mode.
   */
  private DefaultBoxAndWhiskerCategoryDataset prepareBoxPlotDatasetForComparisonModeSignatures(
      int keySizeIndex, List<ResultsModel> resultsModels) {
    DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();

    int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int endModelIndex = (keySizeIndex + 1) * (resultsModels.size() / numKeySizesForComparisonMode);

    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      ResultsModel model = resultsModels.get(modelIndex);

      // Retrieve the hash function for the current combination
      String hashFunctionName = model.getHashFunctionName();
      String keyConfigString = model.getConfigString();
      String seriesName =
          modelIndex + ". " + keyConfigString + " - " + hashFunctionName;

      dataset.add(createBoxAndWhiskerItem(model), seriesName, seriesName);

    }

    return dataset;
  }

  /**
   * Prepares a dataset for a box plot in comparison mode. This method aggregates the statistical
   * data from multiple ResultsModel instances to create a dataset suitable for generating box
   * plots. Each entry in the dataset represents the distribution of benchmarking results for a
   * particular parameter type or key configuration in the comparison mode.
   *
   * @param keyIndex The index of the key size for which the dataset is prepared.
   * @return A box-and-whisker dataset representing the aggregated results for the specified key
   * size.
   */
  private DefaultBoxAndWhiskerCategoryDataset prepareBoxPlotDatasetForComparisonMode(
      int keyIndex, List<ResultsModel> resultsModels, List<String> comparisonModeRowHeaders) {
    DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + numRowsComparisonMode;
        i++) {

      ResultsModel model = resultsModels.get(i);
      String seriesName = i + ". " +
          comparisonModeRowHeaders.get(i % numRowsComparisonMode);

      // Extract necessary statistics and add to dataset
      dataset.add(createBoxAndWhiskerItem(model), seriesName, seriesName);
    }
    return dataset;
  }


  /**
   * Prepares datasets for displaying mean times in a line chart format, specifically for comparison
   * mode. This method creates datasets that visually represent the average execution times and
   * their variance for different results sets, facilitating comparison across various
   * configurations.
   *
   * @param keySizeIndex  The index of the key size for which the datasets are prepared.
   * @param resultsModels A list of ResultsModel objects containing the data for each
   *                      configuration.
   * @return A Pair containing two datasets: one for mean times and one for error intervals.
   */
  private Pair<XYSeriesCollection, YIntervalSeriesCollection> prepareLineChartMeanDatasetForComparisonModeSignatures(
      int keySizeIndex, List<ResultsModel> resultsModels) {
    XYSeriesCollection meanDataset = new XYSeriesCollection();
    YIntervalSeriesCollection errorDataset = new YIntervalSeriesCollection();

    XYSeries meanSeries = new XYSeries("Mean Times");
    YIntervalSeries errorSeries = new YIntervalSeries("Error Bars");

    int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int endModelIndex = (keySizeIndex + 1) * (resultsModels.size() / numKeySizesForComparisonMode);

    // Iterate over each key within the key size range
    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      ResultsModel model = resultsModels.get(modelIndex);

      double mean = model.getMeanData();
      double stdDev = model.getStdDeviationData();

      // X-value for the series should be based on the group index
      int xValue = (modelIndex % (resultsModels.size() / numKeySizesForComparisonMode));

      meanSeries.add(xValue, mean);
      errorSeries.add(xValue, mean, mean - stdDev, mean + stdDev);
    }

    meanDataset.addSeries(meanSeries);
    errorDataset.addSeries(errorSeries);

    return new Pair<>(meanDataset, errorDataset);
  }


  /**
   * Prepares datasets for the mean times line chart in comparison mode. This method aggregates data
   * from multiple ResultsModel instances, creating a dataset suitable for generating line charts.
   * The line chart displays the mean times of operations, aiding in comparing the performance of
   * different parameter sets or key configurations in comparison mode.
   *
   * @param keyIndex      Index of the key size for which the datasets are prepared.
   * @param resultsModels List of ResultsModel objects containing benchmarking data.
   * @return A pair of datasets: one for mean times and one for error intervals.
   */
  private Pair<XYSeriesCollection, YIntervalSeriesCollection> prepareLineChartMeanDatasetForComparisonMode(
      int keyIndex, List<ResultsModel> resultsModels) {
    XYSeriesCollection meanDataset = new XYSeriesCollection();
    YIntervalSeriesCollection errorDataset = new YIntervalSeriesCollection();

    XYSeries meanSeries = new XYSeries("Mean Times");
    YIntervalSeries errorSeries = new YIntervalSeries("Error Bars (Standard Deviation)");

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + numRowsComparisonMode;
        i++) {

      ResultsModel model = resultsModels.get(i);
      double mean = model.getMeanData();
      double stdDev = model.getStdDeviationData();

      int xValue = i % numRowsComparisonMode;

      meanSeries.add(xValue, mean);
      errorSeries.add(xValue, mean, mean - stdDev, mean + stdDev);
    }

    meanDataset.addSeries(meanSeries);
    errorDataset.addSeries(errorSeries);
    return new Pair<>(meanDataset, errorDataset);
  }


  /**
   * Configures the renderers for the line chart displaying mean times.
   *
   * @param plot The plot to which the renderers will be applied.
   */
  private void configureLineChartMeanRenderers(XYPlot plot) {
    // Mean dataset renderer
    XYLineAndShapeRenderer meanRenderer = new XYLineAndShapeRenderer();
    meanRenderer.setSeriesLinesVisible(0, true);
    meanRenderer.setSeriesShapesVisible(0, true);

    plot.setRenderer(0, meanRenderer);

    // Error dataset renderer
    XYErrorRenderer errorRenderer = new XYErrorRenderer();
    errorRenderer.setSeriesLinesVisible(0, true);
    errorRenderer.setSeriesShapesVisible(0, false); // No shapes for error bars
    errorRenderer.setDrawYError(true); // Enable vertical error bars
    errorRenderer.setDrawXError(false); // Disable horizontal error bars
    plot.setRenderer(1, errorRenderer);
  }

  /**
   * Creates a line chart for displaying mean times in comparison mode, allowing visual comparison
   * of performance across different cryptographic configurations.
   *
   * @param meanDataset              The dataset containing mean times for each configuration.
   * @param errorDataset             The dataset containing error intervals for each mean time.
   * @param title                    The title of the line chart.
   * @param comparisonModeRowHeaders Headers used for the rows in comparison mode.
   * @return A JFreeChart object representing the line chart.
   */
  private JFreeChart createLineChartMeanForComparisonMode(XYSeriesCollection meanDataset,
      YIntervalSeriesCollection errorDataset, String title, List<String> comparisonModeRowHeaders) {

    JFreeChart lineChart = ChartFactory.createXYLineChart(
        title,
        "Parameter Type",
        "Mean Time (ms)",
        meanDataset,
        PlotOrientation.VERTICAL,
        true,
        true,
        false
    );

    XYPlot plot = lineChart.getXYPlot();
    plot.setDataset(1, errorDataset); // Set error dataset as secondary dataset
    configureLineChartMeanRenderers(plot);

    String[] paramTypeLabels = new String[numRowsComparisonMode];
    for (int i = 0; i < numRowsComparisonMode; i++) {
      paramTypeLabels[i] = i + ". " + comparisonModeRowHeaders.get(i);
    }

    SymbolAxis xAxis = new SymbolAxis("Parameter Type", paramTypeLabels);
    xAxis.setTickLabelsVisible(true);
    xAxis.setTickLabelFont(new Font("SansSerif", Font.PLAIN, 7));
    plot.setDomainAxis(xAxis);

    return lineChart;
  }


  /**
   * Creates a line chart for mean times, specific to signature operations in comparison mode.
   *
   * @param meanDataset  The dataset for mean times.
   * @param errorDataset The dataset for error intervals.
   * @param title        The title of the chart.
   * @return A JFreeChart object representing the line chart.
   */
  private JFreeChart createLineChartMeanForComparisonModeSignatures(XYSeriesCollection meanDataset,
      YIntervalSeriesCollection errorDataset, String title, List<ResultsModel> resultsModels) {

    JFreeChart lineChart = ChartFactory.createXYLineChart(
        title,
        "Parameter Type",
        "Mean Time (ms)",
        meanDataset,
        PlotOrientation.VERTICAL,
        true,
        true,
        false
    );

    XYPlot plot = lineChart.getXYPlot();
    plot.setDataset(1, errorDataset); // Set error dataset as secondary dataset
    configureLineChartMeanRenderers(plot);

    int modelsPerKeySize = resultsModels.size() / numKeySizesForComparisonMode;
    String[] paramTypeLabels = new String[resultsModels.size() / numKeySizesForComparisonMode];
    for (int i = 0; i < modelsPerKeySize; i++) {
      ResultsModel model = resultsModels.get(i);
      String hashFunctionName = model.getHashFunctionName();
      String keyConfigString = model.getConfigString();
      paramTypeLabels[i] = i + ". " + keyConfigString + " - " + hashFunctionName;
    }

    SymbolAxis xAxis = new SymbolAxis("Parameter Type", paramTypeLabels);
    xAxis.setTickLabelsVisible(true);
    xAxis.setTickLabelFont(new Font("SansSerif", Font.PLAIN, 7));

    plot.setDomainAxis(xAxis);

    return lineChart;
  }


  /**
   * Displays a histogram for a specific key size in comparison mode. This method generates a
   * histogram chart containing results for multiple keys, facilitating comparative analysis.
   *
   * @param keyIndex                 Index of the key size for which the histogram is displayed.
   * @param keyLength                The length of the cryptographic key.
   * @param resultsModels            A list of ResultsModel objects containing benchmarking data.
   * @param comparisonModeRowHeaders Headers for the rows in comparison mode.
   * @param results                  A list of long values representing benchmarking results.
   * @return A ChartViewer containing the stacked histogram.
   */
  public ChartViewer displayStackedHistogram(int keyIndex, int keyLength,
      List<ResultsModel> resultsModels, List<String> comparisonModeRowHeaders, List<Long> results) {
    CategoryDataset dataset;
    if (isSignatureOperationResults) {
      dataset = createStackedHistogramDatasetSignatures(keyIndex, numKeySizesForComparisonMode,
          resultsModels);
    } else {
      dataset = createStackedHistogramDataset(keyIndex, comparisonModeRowHeaders, results,
          resultsModels);
    }
    JFreeChart chart = createStackedHistogramChart(dataset,
        "Stacked Histogram for " + "Key Size " + (keyIndex + 1) + " (" +
            keyLength + "bit)");
    return new ChartViewer(chart);
  }

  /**
   * Creates and displays a histogram for a specific key.
   *
   * @param keyIndex      Index of the key for which the histogram is displayed.
   * @param keyLength     Length of the key for which the histogram is generated.
   * @param resultsModels A list of ResultsModel objects containing benchmarking data.
   * @return A ChartViewer containing the histogram.
   */
  public ChartViewer displayHistogramForKey(int keyIndex, int keyLength,
      List<ResultsModel> resultsModels) {
    CategoryDataset dataset = prepareHistogramForKey(keyIndex, resultsModels);
    JFreeChart chart = createHistogramFromDataset(dataset,
        "Histogram for " + "Key " + (keyIndex + 1) + " (" + keyLength + "bit)");
    return new ChartViewer(chart);
  }

  /**
   * Displays a box plot using the provided dataset.
   *
   * @param dataset           The dataset to be used for the box plot.
   * @param title             The title of the chart.
   * @param categoryAxisLabel The label for the category axis.
   * @return A ChartViewer containing the box plot.
   */
  private ChartViewer displayBoxPlot(DefaultBoxAndWhiskerCategoryDataset dataset, String title,
      String categoryAxisLabel) {
    JFreeChart boxplot = ChartFactory.createBoxAndWhiskerChart(
        title, categoryAxisLabel, "Time (ms)", dataset, true);

    return new ChartViewer(boxplot);
  }

  /**
   * Creates and displays a box plot for benchmarking results of a specific key.
   *
   * @param keyIndex      Index of the key for which the box plot is prepared.
   * @param keyLength     Length of the key for which the box plot is generated.
   * @param resultsModels A list of ResultsModel objects containing benchmarking data.
   * @return A ChartViewer containing the box plot.
   */
  private ChartViewer displayBoxPlotForKey(int keyIndex, int keyLength,
      List<ResultsModel> resultsModels) {
    DefaultBoxAndWhiskerCategoryDataset dataset = prepareBoxPlotDatasetForKey(keyIndex,
        resultsModels);

    // Create the chart
    JFreeChart chart = ChartFactory.createBoxAndWhiskerChart(
        "Box plot for Key " + (keyIndex + 1) + " (" + keyLength + "bit)",    // Title
        "Key " + (keyIndex + 1) + " (" + keyLength + "bit)",
        // X-axis label
        "Time (ms)",               // Y-axis label
        dataset,               // Dataset
        false                  // Not include legend
    );

    CategoryPlot plot = (CategoryPlot) chart.getPlot();
    plot.setDomainGridlinesVisible(true);
    plot.setRangePannable(true);

    NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
    rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
    ChartViewer viewer = new ChartViewer(chart);
    return viewer;
  }


  /**
   * Displays a box plot for benchmarking results in comparison mode. This method generates a
   * box-and-whisker plot that visually represents the distribution of results, such as median and
   * quartiles, for each parameter set or key configuration. It's used to compare performance
   * metrics in a concise and informative way.
   *
   * @param keyIndex                 Index of the key size for which the box plot is displayed.
   * @param keyLength                Length of the key for which the box plot is generated.
   * @param resultsModels            List of ResultsModel objects containing benchmarking data.
   * @param comparisonModeRowHeaders Headers for rows in comparison mode.
   * @return A ChartViewer containing the generated box plot.
   */

  private ChartViewer displayBoxPlotForComparisonMode(int keyIndex, int keyLength,
      List<ResultsModel> resultsModels, List<String> comparisonModeRowHeaders) {
    DefaultBoxAndWhiskerCategoryDataset dataset;
    if (isSignatureOperationResults) {
      dataset = prepareBoxPlotDatasetForComparisonModeSignatures(keyIndex, resultsModels);
    } else {
      dataset = prepareBoxPlotDatasetForComparisonMode(keyIndex, resultsModels,
          comparisonModeRowHeaders);
    }
    return displayBoxPlot(dataset,
        "Box Plot for " + "Key Size " + (keyIndex + 1) + " (" + keyLength + "bit)",
        "Parameter Type");
  }


  /**
   * Displays a line graph for mean times in comparison mode. This method shows a line graph that
   * represents the average performance across different parameter sets or key configurations. This
   * visual representation is especially useful in comparison mode, where multiple configurations
   * are benchmarked against each other.
   *
   * @param keyIndex                 Index of the key size for which the line graph is displayed.
   * @param keyLength                Length of the key used in the benchmarking.
   * @param resultsModels            List of ResultsModel objects containing benchmarking data.
   * @param comparisonModeRowHeaders Headers for rows in comparison mode.
   * @return A ChartViewer containing the line graph.
   */
  private ChartViewer displayLineGraphMeanForComparisonMode(int keyIndex, int keyLength,
      List<ResultsModel> resultsModels, List<String> comparisonModeRowHeaders) {
    Pair<XYSeriesCollection, YIntervalSeriesCollection> datasets;
    if (isSignatureOperationResults) {
      datasets = prepareLineChartMeanDatasetForComparisonModeSignatures(keyIndex, resultsModels);
    } else {
      datasets = prepareLineChartMeanDatasetForComparisonMode(keyIndex, resultsModels);
    }

    XYSeriesCollection meanDataset = datasets.getKey();
    YIntervalSeriesCollection errorDataset = datasets.getValue();
    return isSignatureOperationResults ? new ChartViewer(
        createLineChartMeanForComparisonModeSignatures(meanDataset, errorDataset,
            "Line Graph (Mean) for " + "Key Size " + (keyIndex + 1) + " (" + keyLength + "bit)"
            , resultsModels))
        : new ChartViewer(
            createLineChartMeanForComparisonMode(meanDataset, errorDataset,
                "Line Graph (Mean) for " + "Key Size " + (keyIndex + 1) + " (" + keyLength
                    + "bit)", comparisonModeRowHeaders));

  }


  /**
   * Observer for displaying a histogram view of results for the current key/key size.
   */
  class HistogramButtonObserver implements EventHandler<ActionEvent> {

    private ResultsView resultsView;

    public HistogramButtonObserver(ResultsView resultsView) {
      this.resultsView = resultsView;
    }

    @Override
    public void handle(ActionEvent event) {
      String histogramKey = "Histogram_" + keyIndex;
      ChartViewer viewer = precomputedGraphs.get(histogramKey);
      resultsView.updateGraphArea(viewer);
      lastSelectedGraphButton = resultsView.histogramButton;
    }
  }


  /**
   * Observer for displaying a box plot graph view composed of relevant statistical averages from
   * the results for the current key/key size.
   */
  class BoxPlotButtonObserver implements EventHandler<ActionEvent> {

    private ResultsView resultsView;

    public BoxPlotButtonObserver(ResultsView resultsView) {
      this.resultsView = resultsView;
    }

    @Override
    public void handle(ActionEvent event) {
      String boxPlotKey = "BoxPlot_" + keyIndex;
      ChartViewer viewer = precomputedGraphs.get(boxPlotKey);
      resultsView.updateGraphArea(viewer);
      lastSelectedGraphButton = resultsView.getBoxPlotButton();
    }
  }

  /**
   * Observer for displaying a line graph view with mean times from the results for the current key
   * size in comparison mode.
   */
  class LineGraphButtonMeanObserver implements EventHandler<ActionEvent> {

    private ResultsView resultsView;

    public LineGraphButtonMeanObserver(ResultsView resultsView) {
      this.resultsView = resultsView;
    }

    @Override
    public void handle(ActionEvent event) {
      String lineChartMeanKey = "LineChartMeanTimes_" + keyIndex;
      ChartViewer viewer = precomputedGraphs.get(lineChartMeanKey);
      resultsView.updateGraphArea(viewer);
      lastSelectedGraphButton = resultsView.getLineGraphButtonMean();

    }
  }

  /**
   * Sets the current key index being displayed in the results view.
   *
   * @param keyIndex The index of the key to be set as the current key.
   */
  public void setKeyIndex(int keyIndex) {
    this.keyIndex = keyIndex;
  }

  /**
   * Displays the last selected graph type for the newly selected key size. This method triggers the
   * display of the most recently viewed graph type, ensuring continuity in graph viewing when the
   * key size changes.
   */
  public void displayLastSelectGraphForNewKeySize() {
    lastSelectedGraphButton.fire();
  }

  /**
   * Sets up observers for graph buttons common to both comparison and non-comparison mode. This
   * method adds event handlers to the histogram and box plot buttons in the results view, enabling
   * user interaction for graph switching.
   *
   * @param resultsView The results view that contains the graph buttons.
   */
  public void setupCommonGraphObservers(ResultsView resultsView) {
    resultsView.addHistogramButtonObserver(new HistogramButtonObserver(resultsView));
    resultsView.addBoxPlotButtonObserver(new BoxPlotButtonObserver(resultsView));
  }

  /**
   * Sets up observers specifically for the graph buttons in comparison mode. This method extends
   * the common graph observers setup by adding an observer for the line graph button, allowing
   * users to switch to the line graph view in comparison mode.
   *
   * @param resultsView The results view that contains the graph buttons.
   */
  public void setupComparisonModeGraphObservers(ResultsView resultsView) {
    setupCommonGraphObservers(resultsView);
    resultsView.addLineGraphButtonMeanObserver(new LineGraphButtonMeanObserver(resultsView));
  }


}
