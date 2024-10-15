# read dataset
import pandas as pd
traindata = pd.read_csv("Dataset\TrainingData.csv")


#%% # Xóa các cột không liên quan
traindata.drop(['Unnamed: 0', 'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Timestamp', 'SimillarHTTP', 'Inbound'], axis=1, inplace=True)

# Xóa các cột có giá trị giống nhau hoặc giá trị âm
traindata.drop(['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'FIN Flag Count', 'PSH Flag Count', 'ECE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Active Std', 'Idle Std', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Fwd Header Length.1'], axis=1, inplace=True)


#%% Mã hóa nhãn dữ liệu => số
import numpy as np
traindata.loc[traindata['Label'] == 'BENIGN', 'Label'] = 0
traindata.loc[traindata['Label'] == 'DDoS_DNS', 'Label'] = 1
traindata['Label'] = traindata['Label'].astype(int)
# xóa các giá trị inf, NaN, <0
traindata.replace([np.inf, -np.inf], np.nan, inplace=True)
traindata.dropna(inplace = True)
traindata = traindata[(traindata >= 0).all(axis=1)]


#%% Biến phụ thuộc Y
Y = traindata["Label"].values

#%% Biến độc lập X
X = traindata.drop(labels = ["Label"], axis=1)

#%% Lựa chọn đặc trưng
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif

bestfeatures = SelectKBest(score_func = f_classif, k = 'all')
fit = bestfeatures.fit(X,Y)

tdscores = pd.DataFrame(fit.scores_)
tdcolumns = pd.DataFrame(X.columns)
featureScores = pd.concat([tdcolumns,tdscores],axis=1)
featureScores.columns = ['Columns','Score'] 
print(featureScores.nlargest(10,'Score'))  # in ra 10 đặc trưng tốt nhất

X = X[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets']]


#%% Random Forest
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier(n_estimators = 20, random_state = 42)
model.fit(X, Y)


#%% Cross-validation
from sklearn.model_selection import cross_val_score
cv_scores = cross_val_score(model, X, Y, cv = 10)
print("\nCross-validation: do chinh xac %0.3f voi do lech chuan %0.3f\n." % (cv_scores.mean(), cv_scores.std()))


#%% Đánh giá mô hình bằng dữ liệu test
testdata = pd.read_csv("Dataset\TestingData.csv")
testdata = testdata[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets', 'Label']]
testdata.loc[testdata['Label'] == 'BENIGN', 'Label'] = 0
testdata.loc[testdata['Label'] == 'LDAP', 'Label'] = 1
testdata['Label'] = testdata['Label'].astype(int)
testdata.replace([np.inf, -np.inf], np.nan, inplace=True)
testdata.dropna(inplace = True)
testdata = testdata[(testdata >= 0).all(axis=1)]
X_Test = testdata[['Fwd Packet Length Mean','Avg Fwd Segment Size','Min Packet Length','Fwd Packet Length Min','Packet Length Mean','Protocol','act_data_pkt_fwd','Average Packet Size','Total Fwd Packets','Subflow Fwd Packets']]
Y_Test = testdata["Label"].values

predicted_labels = model.predict(X_Test)


#%% Confusion Matrix
from sklearn.metrics import confusion_matrix
from sklearn.metrics import ConfusionMatrixDisplay
cnf_matrix = confusion_matrix(Y_Test, predicted_labels)
cmd = ConfusionMatrixDisplay(cnf_matrix, display_labels=['Benign\n(Negative)', 'DDoS\n(Positive)'])
cmd.plot()


#%% Precision, Recall & F1
from sklearn.metrics import precision_score, recall_score, f1_score
print('Do chinh xac (Precision): Pre = %.5f' % precision_score(Y_Test, predicted_labels))
print('Do trieu hoi (Recall): Re = %.5f' % recall_score(Y_Test, predicted_labels))
print('Gia tri F1 Score: F1 = %.5f' % f1_score(Y_Test, predicted_labels))
# %%
