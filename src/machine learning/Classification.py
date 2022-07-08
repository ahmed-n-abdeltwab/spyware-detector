import joblib

# filenames
DATA_FN = './data/FinalStaticDataSet.csv'
LOGISTIC_REGRESSION_MODEL = './models/LOGISTIC_REGRESSION_MODEL.joblib'
SUPPORT = './models/SUPPORT.joblib'

def _save(data, fileName):
    # Save the model as a pickle file
    joblib.dump(data, fileName)
   
# reading the csv Data file 
import pandas as pd
df = pd.read_csv(DATA_FN)

#Seperate Data as Features and Labels
X = df.iloc[:,1:-1].values
y = df.iloc[:,0].values


# logistic regression Algorithm
# Set regularization rate
reg = 1

# train a logistic regression model on the training set
from sklearn.linear_model import LogisticRegression

model = LogisticRegression(C=reg, solver="liblinear")

# Features Selection
from sklearn.feature_selection import SelectFromModel
modelSel = SelectFromModel(model.fit(X, y), prefit=True)
selfeat = modelSel.transform(X)
modelSel.get_support()

_save(modelSel.get_support() , SUPPORT)

# Features Scaling
from sklearn.preprocessing import MinMaxScaler
sel = MinMaxScaler()
SclFeat = sel.fit_transform(selfeat,y)

# Split Data as Trainning set and Test set  
from sklearn.model_selection import train_test_split
X_train, X_test,y_train, y_test = train_test_split(SclFeat, y, test_size = 0.3, random_state = 1)


# Fitting Data
model.fit(X_train, y_train)

# save the model in the dirctory
_save(model , LOGISTIC_REGRESSION_MODEL)

# Test Model

# Make Predictions
predictions = model.predict(X_test)
# Make Predictions
predictionsTrain = model.predict(X_train)


# Get Probability od Predictions 
PredictProba = model.predict_proba(X_test)


# Get Accuracy , Precision and Recall
from sklearn.metrics import accuracy_score, precision_score, recall_score
accuracy  = accuracy_score(y_test, predictions)
precision = precision_score(y_test,  predictions)
recall    = recall_score(y_test,  predictions)
performance = {"Accuracy": accuracy,
               "Precision": precision,
               "Recall": recall}

# Visualize Performance
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report

print(classification_report(y_test, predictions))
# Get evaluation metrics
cm = confusion_matrix(y_test, predictions)
print('Confusion Matrix:\n', cm, '\n')
print('Accuracy:', performance["Accuracy"])
print("Overall Precision:",  performance["Precision"])
print("Overall Recall:", performance["Recall"])
auc = roc_auc_score(y_test, PredictProba[:, 1])
print('AUC: ' + str(auc))

# calculate ROC curve
import matplotlib.pyplot as plt
fpr, tpr, thresholds = roc_curve(y_test, PredictProba[:, 1])

# plot ROC curve
fig = plt.figure(figsize=(6, 6))
# Plot the diagonal 50% line
plt.plot([0, 1], [0, 1], 'k--')
# Plot the FPR and TPR achieved by our model
plt.plot(fpr, tpr)
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.show()
