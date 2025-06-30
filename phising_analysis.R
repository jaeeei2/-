
# 부록 R코드

#========================
#==== 데이터 준비 =======
#========================
library(dplyr)
library(ggplot2)
library(car)
library(randomForest) #rf model
library(caret) # feature selection
library(e1071) # model tuning
library(ROCR) # model evaluation
library(gridExtra) # grid layouts
library(pastecs) # details summary stats
library(ggplot2) # visualizations
library(gmodels) # build contingency tables
library(rpart)# tree models
library(rpart.plot)
library(pastecs)
library(gridExtra)
library(corrplot)

# 데이터 불러오기
phishing_data <- read.csv("Phishing.csv", header = TRUE)

# 최종 분석에 사용할 변수 10개 + 종속변수 1개
used.vars <- c('NumDash', 'NumNumericChars', 'PctExtHyperlinks',
               'NumSensitiveWords', 'PctNullSelfRedirectHyperlinks',
               'SubmitInfoToEmail', 'FrequentDomainNameMismatch',
               'PctExtResourceUrlsRT', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT',
               'CLASS_LABEL'
)
phishing_data = subset(phishing_data, select=used.vars)

# 종속변수 변수명 변경 CLASS_LABEL -> Phishing
colnames(phishing_data) <- c('NumDash', 'NumNumericChars', 'PctExtHyperlinks',
                             'NumSensitiveWords', 'PctNullSelfRedirectHyperlinks',
                             'SubmitInfoToEmail', 'FrequentDomainNameMismatch',
                             'PctExtResourceUrlsRT', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT',
                             'Phishing')

# 데이터 구조 확인
class(phishing_data)
head(phishing_data, n=3)
str(phishing_data)  
dim(phishing_data) # 10000*11

# 범주형 레이블링 통일
library(car)
new.ExtMetaScriptLinkRT <- car::recode(phishing_data$ExtMetaScriptLinkRT, "0=-1;-1=0;1=1")
phishing_data$ExtMetaScriptLinkRT <- new.ExtMetaScriptLinkRT

new.PctExtNullSelfRedirectHyperlinksRT <- car::recode(phishing_data$PctExtNullSelfRedirectHyperlinksRT, "1=-1;0=0;-1=1")
phishing_data$PctExtNullSelfRedirectHyperlinksRT <- new.PctExtNullSelfRedirectHyperlinksRT

#new.SubmitInfoToEmail <- car::recode(phishing_data$SubmitInfoToEmail, "0=1;1=0")
#phishing_data$SubmitInfoToEmail <- new.SubmitInfoToEmail

# 결측값 확인
sum(is.na(phishing_data)) # 0
colSums(is.na(phishing_data))
sum(complete.cases(phishing_data))

# 분산이 0 또는 0에 가까운 변수 처리
library(caret)
feature_variances <- caret::nearZeroVar(phishing_data, saveMetrics = TRUE)
which(feature_variances$zeroVar == 'TRUE') # X

# 범주형 factor 변환
categorical.vars <- c('SubmitInfoToEmail', 'FrequentDomainNameMismatch',
                      'PctExtResourceUrlsRT', 'ExtMetaScriptLinkRT',
                      'PctExtNullSelfRedirectHyperlinksRT', 'Phishing')
phishing_data <- to.factors(df = phishing_data, variables = categorical.vars)

# 수치형 변수
numeric.vars <- c('NumDash', 'NumNumericChars', 'PctExtHyperlinks',
                  'NumSensitiveWords', 'PctNullSelfRedirectHyperlinks')

# 데이터 구조 재확인
class(phishing_data)
head(phishing_data, n=3)
str(phishing_data)  
dim(phishing_data) # 10000*11

#========================
#=== 범주형 변수 EDA ====
#========================
# 함수 생성

# summary statistics
get.categorical.variable.stats <- function(indep.var){
  
  feature.name = deparse(substitute(indep.var))
  df1 <- data.frame(table(indep.var))
  colnames(df1) <- c(feature.name, "Frequency")
  df2 <- data.frame(prop.table(table(indep.var)))
  colnames(df2) <- c(feature.name, "Proportion")
  
  df <- merge(
    df1, df2, by = feature.name
  )
  ndf <- df[order(-df$Frequency),]
  if (names(dev.cur()) != "null device"){
    dev.off()
  }
  grid.table(ndf)
}

#generate contingency table
get.contingency.table <- function(dep.var, indep.var, stat.tests=F){
  if(stat.tests == F){
    CrossTable(dep.var, indep.var, digits=1,
               prop.r=F, prop.t=F, prop.chisq=F)
  }else{
    CrossTable(dep.var, indep.var, digits=1,
               prop.r=F, prop.t=F, prop.chisq=F,
               chisq=T, fisher=T)
  }
}

# visualizations
# barcharts
visualize.barchart <- function(indep.var){
  qplot(indep.var, geom="bar",
        fill=I('gray'), col=I('black'),
        xlab = deparse(substitute(indep.var))) + theme_bw()
}

# mosaic plots
visualize.contingency.table <- function(dep.var, indep.var){
  if (names(dev.cur()) != "null device"){
    dev.off()
  }
  mosaicplot(dep.var ~ indep.var, color=T,
             main = "", 
             xlab = "Phishing", ylab= deparse(substitute(indep.var)))
}

# 범주형 변수 빈도표

## FrequentDomainNameMismatch (도메인 이름 불일치) 
# 빈도표
table(FrequentDomainNameMismatch)
ggplot(data=phishing_data, aes(x=factor(FrequentDomainNameMismatch))) +
  geom_bar(fill="grey", color="black") +
  ggtitle("도메인 이름 불일치") + xlab("FrequentDomainNameMismatch") +
  scale_x_discrete(labels=c("0", "1"))

## SubmitInfoToEmail (메일 보내기 기능 존재) 
# 빈도표
table(SubmitInfoToEmail)
ggplot(data=phishing_data, aes(x=factor(SubmitInfoToEmail))) +
  geom_bar(fill="grey", color="black") +
  ggtitle("메일 보내기 기능 존재") + xlab("SubmitInfoToEmail") +
  scale_x_discrete(labels=c("0", "1"))

## PctExtResourceUrlsRT (외부 리소스 코드 비율) 
# 빈도표
table(PctExtResourceUrlsRT)
ggplot(data=phishing_data, aes(x=factor(PctExtResourceUrlsRT))) +
  geom_bar(fill="grey", color="black") +
  ggtitle("외부 리소스 코드 비율") + xlab("PctExtResourceUrlsRT") +
  scale_x_discrete(labels=c("0", "1"))

## ExtMetaScriptLinkRT (외부 파일 코드 비율)
# 빈도표
table(ExtMetaScriptLinkRT)
ggplot(data=phishing_data, aes(x=factor(ExtMetaScriptLinkRT))) +
  geom_bar(fill="grey", color="black") +
  ggtitle("외부 파일 코드 비율") + xlab("ExtMetaScriptLinkRT") +
  scale_x_discrete(labels=c("0", "1"))

## PctExtNullSelfRedirectHyperlinksRT (비정상 동작 처리 하이퍼링크 코드 비율)
# 빈도표
table(PctExtNullSelfRedirectHyperlinksRT)
ggplot(data=phishing_data, aes(x=factor(PctExtNullSelfRedirectHyperlinksRT))) +
  geom_bar(fill="grey", color="black") +
  ggtitle("비정상 동작 처리 하이퍼링크 코드 비율") + xlab("PctExtNullSelfRedirectHyperlinksRT") +
  scale_x_discrete(labels=c("0", "1"))


# 범주형 변수 - 종속변수 
#모자이크 그림, 카이제곱 검정

options("scipen" = 100)

## SubmitInfoToEmail (메일 보내기 기능 존재) 
# generate contingency table
get.contingency.table(Phishing, SubmitInfoToEmail, stat.tests = T)
# visualizations
visualize.contingency.table(Phishing, SubmitInfoToEmail)

## FrequentDomainNameMismatch (도메인 이름 불일치) 
# generate contingency table
get.contingency.table(Phishing, FrequentDomainNameMismatch, stat.tests = T)
# visualizations
visualize.contingency.table(Phishing, FrequentDomainNameMismatch)

## PctExtResourceUrlsRT (외부 리소스 코드 비율) 
# generate contingency table
get.contingency.table(Phishing, PctExtResourceUrlsRT, stat.tests = T)
# visualizations
visualize.contingency.table(Phishing, PctExtResourceUrlsRT)

## ExtMetaScriptLinkRT (외부 파일 코드 비율)
# generate contingency table
get.contingency.table(Phishing, ExtMetaScriptLinkRT, stat.tests = T)
# visualizations
visualize.contingency.table(Phishing, ExtMetaScriptLinkRT)

# -> 피셔정확검정 에러 수정 버전 코드 - 실제 분석에는 카이제곱 결과 활용
tab = data.frame(Phishing, ExtMetaScriptLinkRT) 
table(tab)
fisher.test(table(tab), workspace = 2e8)

## PctExtNullSelfRedirectHyperlinksRT (비정상 동작 처리 하이퍼링크 코드 비율)
# generate contingency table
get.contingency.table(Phishing, PctExtNullSelfRedirectHyperlinksRT, stat.tests = T)
# visualizations
visualize.contingency.table(Phishing, PctExtNullSelfRedirectHyperlinksRT)

# 범주별 피싱 비율 - 교차표에서도 계산 가능, 0.9 이상, 0.1 이하인 경우만 설명에 포함

## FrequentDomainNameMismatch (도메인 이름 불일치) 
temp_data <- phishing_data %>% 
  group_by(FrequentDomainNameMismatch, Phishing) %>% 
  summarise(total = n())
temp_data %>% 
  group_by(FrequentDomainNameMismatch) %>% 
  mutate(percent = total / sum(total))

## SubmitInfoToEmail (메일 보내기 기능 존재) 
temp_data <- phishing_data %>% 
  group_by(SubmitInfoToEmail, Phishing) %>% 
  summarise(total = n())
temp_data %>% 
  group_by(SubmitInfoToEmail) %>% 
  mutate(percent = total / sum(total))

## PctExtResourceUrlsRT (외부 리소스 코드 비율) 
temp_data <- phishing_data %>% 
  group_by(PctExtResourceUrlsRT, Phishing) %>% 
  summarise(total = n())
temp_data %>% 
  group_by(PctExtResourceUrlsRT) %>%
  mutate(percent = total / sum(total))

## ExtMetaScriptLinkRT (외부 파일 코드 비율)
temp_data <- phishing_data %>% 
  group_by(ExtMetaScriptLinkRT, Phishing) %>% 
  summarise(total = n())
temp_data %>% 
  group_by(ExtMetaScriptLinkRT) %>% 
  mutate(percent = total / sum(total))

## PctExtNullSelfRedirectHyperlinksRT (비정상 동작 처리 하이퍼링크 코드 비율)
temp_data <- phishing_data %>% 
  group_by(PctExtNullSelfRedirectHyperlinksRT, Phishing) %>% 
  summarise(total = n())
temp_data %>% 
  group_by(PctExtNullSelfRedirectHyperlinksRT) %>% 
  mutate(percent = total / sum(total))

#========================
#=== 연속형 변수 EDA ====
#========================
# 함수 생성

# summary statistics
get.numeric.variable.stats <- function(indep.var, detailed=FALSE){
  options(scipen=100)
  options(digits=2)
  if (detailed){
    var.stats <- stat.desc(indep.var)
  }else{
    var.stats <- summary(indep.var)
  }
  
  df <- data.frame(round(as.numeric(var.stats),2))
  colnames(df) <- deparse(substitute(indep.var))
  rownames(df) <- names(var.stats)
  
  if (names(dev.cur()) != "null device"){
    dev.off()
  }
  grid.table(t(df))
}

# visualizations
# histograms\density
visualize.distribution <- function(indep.var){
  pl1 <- qplot(indep.var, geom="histogram",
               fill=I('gray'), binwidth=5,
               col=I('black'))+ theme_bw()
  pl2 <- qplot(indep.var, geom="density",
               fill=I('gray'), binwidth=5,
               col=I('black'))+ theme_bw()
  
  grid.arrange(pl1,pl2, ncol=2)
}

# box plots
visualize.boxplot <- function(indep.var, dep.var){
  pl1 <- qplot(factor(0),indep.var, geom="boxplot",
               xlab = deparse(substitute(indep.var)),
               ylab="values") + theme_bw()
  pl2 <- qplot(dep.var,indep.var,geom="boxplot",
               xlab = deparse(substitute(dep.var)),
               ylab = deparse(substitute(indep.var))) + theme_bw()
  
  grid.arrange(pl1,pl2, ncol=2)
}

# 연속형 변수 - 종속변수 

## NumSensitiveWords(민감한 단어 개수) 
# 기초통계량
get.numeric.variable.stats(NumSensitiveWords)
# histogram
ggplot(phishing_data, aes(x=NumSensitiveWords,fill=Phishing))+xlab("민감한 단어의 수") + geom_histogram(bins=4, alpha=0.7)
# box-plot
ggplot(phishing_data, aes(x=Phishing, y=NumSensitiveWords)) +
  geom_boxplot(aes(fill = Phishing)) +
  xlab("Phishing") + ylab("민감한 단어의 수") +
  labs(fill = "Phishing")

## PctExtHyperlinks(하이퍼링크 비율) 
# 기초통계량
get.numeric.variable.stats(PctExtHyperlinks)
# histogram
ggplot(phishing_data, aes(x=PctExtHyperlinks,fill=Phishing)) + xlab("하이퍼링크 코드 비율") + geom_histogram(bins=10, alpha=0.7)
# box-plot
ggplot(phishing_data, aes(x=Phishing, y=PctExtHyperlinks)) +
  geom_boxplot(aes(fill = Phishing)) +
  xlab("Phishing") + ylab("하이퍼링크 코드 비율")  +
  labs(fill = "Phishing")


## PctNullSelfRedirectHyperlinks(비정상링크 하이퍼링크 코드 비율)
# 기초통계량
get.numeric.variable.stats(PctNullSelfRedirectHyperlinks)
# histogram
ggplot(phishing_data, aes(x=PctNullSelfRedirectHyperlinks,fill=Phishing)) + xlab("비정상링크 하이퍼링크 코드 비율")+geom_histogram(bins=6, alpha=0.7)
#box-plot
ggplot(phishing_data, aes(x=Phishing, y=PctNullSelfRedirectHyperlinks)) +
  geom_boxplot(aes(fill = Phishing)) +
  xlab("Phishing") + ylab("비정상링크 하이퍼링크 코드 비율") +
  labs(fill = "Phishing")

# 연속형 변수 간 상관성 분석
phishing_col <- phishing_data[,1:5]
phishing_col
ps <- cor(phishing_col,phishing_col[c(1:5)])
col <- colorRampPalette(c("#BB4444", "#EE9988", "#FFFFFF", "#77AADD", "#4477AA"))
corrplot(ps,method = "shade", shade.col = NA, tl.col = "black", tl.srt = 45, col=col(200), addCoef.col = "black")

#====================
#==== 모델링  =======
#====================

# 연속형 스케일링
scale.features <- function(df, variables){
  for (variable in variables){
    df[[variable]] <- scale(df[[variable]], center=T, scale=T)
  }
  return(df)
}
phishing_data <- scale.features(phishing_data, numeric.vars)
head(phishing_data, n=3) 

# 훈련용 6 : 테스트용 4 분리
indexes <- sample(1:nrow(phishing_data), size=0.6*nrow(phishing_data))
train.data <- phishing_data[indexes,]
test.data <- phishing_data[-indexes,]
nrow(train.data) ; nrow(test.data) # 6000 4000

get.categorical.variable.stats(train.data$Phishing) # 종속변수 비율 확인 
get.categorical.variable.stats(test.data$Phishing) # 종속변수 비율 확인 

test.feature.vars <- test.data[,-11] # 독립변수
test.class.var <- test.data[,11] # 종속변수

# 모델링 

########################
#### 로지스틱 회귀 #####
########################

#----------------------------------------
#--- 전체 모형 (변수 10개 모두 사용) ----
#----------------------------------------

## 전체 모형 생성
formula.init <- "Phishing ~ ." 
formula.init <- as.formula(formula.init)
lr.model <- glm(formula=formula.init, data=train.data, family="binomial")
summary(lr.model) 

## 전체 모형 예측 & 혼동행렬 출력
lr.predictions <- predict(lr.model, test.data, type="response") 
lr.predictions <- as.factor(round(lr.predictions)) 
confusionMatrix(data=lr.predictions, reference=test.class.var, positive='1') 

## 전체 모형 성능 평가 ROC curve
lr.model.best <- lr.model
lr.prediction.values <- predict(lr.model.best, test.feature.vars, type="response")
predictions <- prediction(lr.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="LR ROC Curve")
plot.pr.curve(predictions, title.text="LR Precision/Recall Curve")

#--------------------
#--- 축소 모형 ------
#--------------------

## 축소 모형 생성
formula <- "Phishing ~ ."
formula <- as.formula(formula)
control <- trainControl(method="repeatedcv", number=10, repeats=2)
model <- train(formula, data=train.data, method="glm", 
               trControl=control)

## 변수 중요도 그래프
importance <- varImp(model, scale=FALSE) 
plot(importance, scales = list(y = list(cex = 0.5))) 

## 축소 모형 생성
formula.new <- "Phishing ~ PctExtNullSelfRedirectHyperlinksRT + PctExtHyperlinks + ExtMetaScriptLinkRT + SubmitInfoToEmail + FrequentDomainNameMismatch + NumDash + PctNullSelfRedirectHyperlinks + NumSensitiveWords"
formula.new <- as.formula(formula.new)
lr.model.new <- glm(formula=formula.new, data=train.data, family="binomial")
summary(lr.model.new)

## 축소 모형 예측 & 혼동행렬 도출
lr.predictions.new <- predict(lr.model.new, test.data, type="response") 
lr.predictions.new <- as.factor(round(lr.predictions.new))
confusionMatrix(data=lr.predictions.new, reference=test.class.var, positive='1') # 'Positive' Class 확인 / x축 y축 확인

## 축소 모형 성능 평가 ROC curve
lr.model.best <- lr.model.new
lr.prediction.values <- predict(lr.model.best, test.feature.vars, type="response")
predictions <- prediction(lr.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="LR ROC Curve")
plot.pr.curve(predictions, title.text="LR Precision/Recall Curve")


##########################
#### 서포트벡터 머신 #####
##########################

#----------------------------------------
#--- 전체 모형 (변수 10개 모두 사용) ----
#----------------------------------------

## 전체 모형 생성
formula.init="Phishing ~ ."
formula.init=as.formula(formula.init)
svm.model=svm(formula=formula.init, data=train.data, 
              kernel="radial", cost=100, gamma=1)
summary(svm.model)

## 전체 모형 예측 & 혼동행렬 출력
svm.predictions=predict(svm.model, test.feature.vars, decision.values = T) 
confusionMatrix(data=svm.predictions, reference=test.class.var, positive="1")


## 전체 모형 성능 평가 ROC curve
svm.prediction.values <- attributes(svm.predictions)$decision.values
predictions <- prediction(svm.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="SVM ROC Curve") 
plot.pr.curve(predictions, title.text="SVM Precision/Recall Curve")

#--------------------
#--- 축소 모형 ------
#--------------------

## SVM 변수 중요도 그래프
formula.init <- "Phishing ~ ."
formula.init <- as.formula(formula.init)
control <- trainControl(method="repeatedcv", number=10, repeats=2)
model <- train(formula.init, data=train.data, method="svmRadial", 
               trControl=control)
importance <- varImp(model, scale=FALSE)
plot(importance, cex.lab=0.5)


## 축소 모형 생성
formula.new <- "Phishing ~ PctExtNullSelfRedirectHyperlinksRT+ExtMetaScriptLinkRT+
                              FrequentDomainNameMismatch+
                              NumDash+NumNumericChars+SubmitInfoToEmail+
                              PctExtHyperlinks+NumSensitiveWords"

formula.new <- as.formula(formula.new)
svm.model.new <- svm(formula=formula.new, data=train.data, 
                     kernel="radial", cost=10, gamma=0.25)
summary(svm.model.new)
svm.predictions.new <- predict(svm.model.new, test.feature.vars)
confusionMatrix(data=svm.predictions.new, reference=test.class.var, positive="1")


## 하이퍼파라미터 변수 최적화

# run grid search
cost.weights <- c(0.1, 10, 100)
gamma.weights <- c(0.01, 0.25, 0.5, 1)
tuning.results <- tune(svm, formula.new, 
                       data = train.data, kernel="radial", 
                       ranges=list(cost=cost.weights, gamma=gamma.weights))
print(tuning.results)
plot(tuning.results, cex.main=0.6, cex.lab=0.8,xaxs="i", yaxs="i")

## 축소 모형 예측 & 혼동행렬 출력
svm.model.best = tuning.results$best.model
svm.predictions.best <- predict(svm.model.best, test.feature.vars)
confusionMatrix(data=svm.predictions.best, reference=test.class.var, positive="1") 

## 축소 모형 성능 평가 ROC curve
svm.predictions.best <- predict(svm.model.best, test.feature.vars, decision.values = T)
svm.prediction.values <- attributes(svm.predictions.best)$decision.values
predictions <- prediction(svm.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="SVM ROC Curve") 
plot.pr.curve(predictions, title.text="SVM Precision/Recall Curve")


#######################
#### 의사결정나무 #####
#######################

#----------------------------------------
#--- 전체 모형 (변수 10개 모두 사용) ----
#----------------------------------------

## 전체 모형 생성
# cp:complexity parameters, minsplit:최소데이터 수 
formula.init <- "Phishing ~ ."
formula.init <- as.formula(formula.init)
dt.model <- rpart(formula=formula.init, method="class",data=train.data)
dt.model$cptable # cp=0.01가 적당한 값임을 확인
dt.model <- rpart(formula=formula.init, method="class",data=train.data, 
                  control = rpart.control(minsplit=20, cp=0.01)) 
dt.model$cptable # cp=0.01가 적당한 값임을 확인
plotcp(dt.model)

## 전체 모형 예측 & 혼동행렬 출력
dt.predictions <- predict(dt.model, test.feature.vars, type="class")
confusionMatrix(data=dt.predictions, reference=test.class.var, positive="1")

## 전체 모형 성능 평가 ROC curve
dt.predictions <- predict(dt.model, test.feature.vars, type="prob")
dt.prediction.values <- dt.predictions[,2] 
predictions <- prediction(dt.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="DT ROC Curve")
plot.pr.curve(predictions, title.text="DT Precision/Recall Curve")

#--------------------
#--- 축소 모형 ------
#--------------------

## dt specific feature selection
# k(number)-fold cross validation을 10개의 fold를 만들어 2번 반복(repeats=2) 
control <- trainControl(method="repeatedcv", number=10, repeats=2)
model <- train(formula.init, data=train.data, method="rpart", 
               trControl=control)

# 변수 중요도 그래프
importance <- varImp(model, scale=FALSE)
plot(importance, cex.lab=0.5)

## 축소 모형 생성
formula.new <- "Phishing ~ PctExtHyperlinks + FrequentDomainNameMismatch + PctExtNullSelfRedirectHyperlinksRT + ExtMetaScriptLinkRT + NumDash"
formula.new <- as.formula(formula.new)
dt.model.new <- rpart(formula=formula.new, method="class",data=train.data, 
                      control = rpart.control(minsplit=20, cp=0.01),
                      parms = list(prior = c(0.5, 0.5)))

## 축소 모형 예측 & 혼동행렬 출력 
dt.predictions.new <- predict(dt.model.new, test.feature.vars, type="class")
confusionMatrix(data=dt.predictions.new, reference=test.class.var, positive="1")

## 축소 모형 성능 평가 ROC curve
dt.predictions.best <- predict(dt.model.new, test.feature.vars, type="prob")
dt.prediction.values.best <- dt.predictions.best[,2] 
predictions.best <- prediction(dt.prediction.values.best, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions.best, title.text="DT ROC Curve")
plot.pr.curve(predictions.best, title.text="DT Precision/Recall Curve")

## 최종모델 결정
dt.model.best <- dt.model.new
print(dt.model.best)
par(mfrow=c(1,1))

## 의사결정나무 시각화
prp(dt.model.best, type=4, extra=1, varlen=0, faclen=0, box.palette = "Grays")


########################
#### 랜덤 포레스트 #####
########################

#----------------------------------------
#--- 전체 모형 (변수 10개 모두 사용) ----
#----------------------------------------

## 전체 모형 생성
formula.init <- "Phishing ~ ."
formula.init <- as.formula(formula.init)
rf.model.all <- randomForest(formula.init, data = train.data, importance=T, proximity=T)
print(rf.model.all)

## 전체 모형 예측 & 혼동행렬 출력
rf.predictions.all <- predict(rf.model.all, test.feature.vars, type="class")
confusionMatrix(data=rf.predictions.all, reference=test.class.var, positive="1")

## 전체 모형 성능 평가 ROC curve
rf.predictions.all <- predict(rf.model.all, test.feature.vars, type="prob")
rf.prediction.all <- rf.predictions.all[,2]
predictions.all <- prediction(rf.prediction.all, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions.all, title.text="RF ROC Curve")
plot.pr.curve(predictions.all, title.text="RF Precision/Recall Curve")


#--------------------
#--- 축소 모형 ------
#--------------------

# rfe based feature selection algorithm
run.feature.selection <- function(num.iters=20, feature.vars, class.var){
  set.seed(10)
  variable.sizes <- 1:10
  control <- rfeControl(functions = rfFuncs, method = "cv", 
                        verbose = FALSE, returnResamp = "all", 
                        number = num.iters)
  results.rfe <- rfe(x = feature.vars, y = class.var, 
                     sizes = variable.sizes, 
                     rfeControl = control)
  return(results.rfe)
}

# run feature selection
rfe.results <- run.feature.selection(feature.vars=train.data[,-11], 
                                     class.var=train.data[,11])
rfe.results

## 변수 중요도 그래프
importance(rf.model.fs)
plot(importance(rf.model.fs))
varImpPlot(rf.model.fs)

# hyperparameter optimization
nodesize.vals <- c(2, 3, 4, 5)
ntree.vals <- c(200, 500, 1000, 2000)
tuning.results <- tune.randomForest(formula.fs, 
                                    data = train.data,
                                    mtry=3, 
                                    nodesize=nodesize.vals,
                                    ntree=ntree.vals)
print(tuning.results)

## 축소 모형 예측 & 혼동행렬 출력
rf.model.best <- tuning.results$best.model
rf.predictions.best <- predict(rf.model.best, test.feature.vars, type="class")
confusionMatrix(data=rf.predictions.best, reference=test.class.var, positive="1")
print(rf.model.best)

## 축소 모형 성능 평가 ROC curve
rf.predictions.best <- predict(rf.model.best, test.feature.vars, type="prob")
rf.prediction.values <- rf.predictions.best[,2]
predictions <- prediction(rf.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="RF ROC Curve")
plot.pr.curve(predictions, title.text="RF Precision/Recall Curve")


#####################
#### 인공신경망 #####
#####################

transformed.train <- train.data
transformed.test <- test.data
for (variable in categorical.vars){
  new.train.var <- make.names(train.data[[variable]])
  transformed.train[[variable]] <- new.train.var
  new.test.var <- make.names(test.data[[variable]])
  transformed.test[[variable]] <- new.test.var
}
transformed.train <- to.factors(df=transformed.train, variables=categorical.vars)
transformed.test <- to.factors(df=transformed.test, variables=categorical.vars)
transformed.test.feature.vars <- transformed.test[,-11]
transformed.test.class.var <- transformed.test[,11]

#----------------------------------------
#--- 전체 모형 (변수 10개 모두 사용) ----
#----------------------------------------

## 전체 모형 생성
formula.init <- "Phishing ~ ."
formula.init <- as.formula(formula.init)
nn.model <- train(formula.init, data = transformed.train, method="nnet")
print(nn.model)

## 전체 모형 예측 & 혼동행렬 출력
nn.predictions <- predict(nn.model, transformed.test.feature.vars, type="raw")
confusionMatrix(data=nn.predictions, reference=transformed.test.class.var, 
                positive="X1")

## 전체 모형 성능 평가 ROC curve
nn.model.best <- nn.model
nn.predictions.best <- predict(nn.model.best, transformed.test.feature.vars, type="prob")
nn.prediction.values <- nn.predictions.best[,2]
predictions <- prediction(nn.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="NN ROC Curve")
plot.pr.curve(predictions, title.text="NN Precision/Recall Curve")

#--------------------------
#--- 축소 모형1 (8개) ------
#--------------------------

# nn specific feature selection
formula.init <- "Phishing ~ ."
formula.init <- as.formula(formula.init)
control <- trainControl(method="repeatedcv", number=10, repeats=2)
model <- train(formula.init, data=transformed.train, method="nnet", 
               trControl=control)

## 변수 중요도 그래프
importance <- varImp(model, scale=FALSE)
plot(importance, cex.lab=0.5)

## 축소 모형1 생성 (Top8)
formula.new8 <- "Phishing ~ PctNullSelfRedirectHyperlinks + PctExtNullSelfRedirectHyperlinksRT + PctExtHyperlinks + PctExtResourceUrlsRT + NumNumericChars + SubmitInfoToEmail + ExtMetaScriptLinkRT + NumDash"
formula.new8 <- as.formula(formula.new8)
nn.model.new8 <- train(formula.new8, data=transformed.train, method="nnet")
print(nn.model.new8)

## 축소 모형1 예측 & 혼동행렬 출력
nn.predictions.new8 <- predict(nn.model.new8, transformed.test.feature.vars, type="raw")
confusionMatrix(data=nn.predictions.new8, reference=transformed.test.class.var, 
                positive="X1")

## 축소 모형1 성능 평가 ROC curve
nn.model.best <- nn.model.new8
nn.predictions.best <- predict(nn.model.best, transformed.test.feature.vars, type="prob")
nn.prediction.values <- nn.predictions.best[,2]
predictions <- prediction(nn.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="NN ROC Curve")
plot.pr.curve(predictions, title.text="NN Precision/Recall Curve")

#--------------------------
#--- 축소 모형2 (7개) ------
#--------------------------

## 축소 모형2 생성 (Top7)
formula.new7 <- "Phishing ~ PctNullSelfRedirectHyperlinks + PctExtNullSelfRedirectHyperlinksRT + PctExtHyperlinks + PctExtResourceUrlsRT + NumNumericChars + SubmitInfoToEmail + ExtMetaScriptLinkRT"
formula.new7 <- as.formula(formula.new7)
nn.model.new7 <- train(formula.new7, data=transformed.train, method="nnet")
print(nn.model.new7)

## 축소 모형2 예측 & 혼동행렬 출력
nn.predictions.new7 <- predict(nn.model.new7, transformed.test.feature.vars, type="raw")
confusionMatrix(data=nn.predictions.new7, reference=transformed.test.class.var, 
                positive="X1")

## 축소 모형2 성능 평가 ROC curve
nn.model.best <- nn.model.new7
nn.predictions.best <- predict(nn.model.best, transformed.test.feature.vars, type="prob")
nn.prediction.values <- nn.predictions.best[,2]
predictions <- prediction(nn.prediction.values, test.class.var)
par(mfrow=c(1,2))
plot.roc.curve(predictions, title.text="NN ROC Curve")
plot.pr.curve(predictions, title.text="NN Precision/Recall Curve")

### end ###