package uk.msci.project.rsa;

import javafx.beans.value.ChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Node;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.StackPane;

public interface SignatureViewInterface {

  ImageView getTextFileCheckmarkImage();

  void setTextFileCheckmarkImage();

  ImageView getCheckmarkImage();

  void setCheckmarkImage();

  void setCheckmarkImageVisibility(boolean visible);

  String getTextInput();

  void setTextInput(String text);

  void setTextInputVisibility(boolean visible);

  void setTextInputHBoxVisibility(boolean visible);

  String getKey();

  void setKey(String key);

  void setKeyVisibility(boolean visible);

  String getSelectedSignatureScheme();

  void setSelectedSignatureScheme(String scheme);

  String getTextFileNameLabel();

  void setTextFileNameLabel(String fileName);

  void setImportTextButtonLabel(String label);

  String getImportTextButtonLabel();

  StackPane getNotificationPane();

  void setRecoveryOptionsVisibility(boolean visible);

  void addImportTextObserver(EventHandler<ActionEvent> observer);


  void addBackToMainMenuObserver(EventHandler<ActionEvent> observer);

  void addHelpObserver(EventHandler<ActionEvent> observer);

  void addImportKeyObserver(EventHandler<ActionEvent> observer);

  void addSignatureSchemeChangeObserver(ChangeListener<String> observer);

  void addCloseNotificationObserver(EventHandler<ActionEvent> observer);

  void showNotificationPane();

}
