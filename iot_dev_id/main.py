#!/usr/bin/env python3

import time, matplotlib
from iot_dev_id.feat import *
# Decision trees
from sklearn import tree
# ML model persistence
from joblib import dump, load

PTH_PCAPS_TRN = '../dss/trn-fnl'
PTH_PCAPS_TEST = '../dss/test-fnl'
PTH_DEVS = './devs.csv'
PTH_OUT_FEAT_TRN = './feats-trn.csv'
PTH_OUT_FEAT_TEST = './feats-test.csv'
PTH_FIG = './tree-type.png'
PTH_CLF = './clfs/type.joblib'
PRED_TGT = Tgt.TYPE

def trn(clf, feats, lbls):
    print('---------- Training Phase ----------')
    print('Total # of training samples: {}'.format(len(lbls)))

    strt = time.time()
    clf.fit(feats, lbls)
    end = time.time()
    # print('Training time: {:.3f} sec.'.format(end - strt))
    print('Training time: {} sec.'.format(end - strt))

    # ----- Plot trained decision tree. -----
    strt = time.time()
    fig, axes = matplotlib.pyplot.subplots(figsize=(80, 80))
    tree.plot_tree(clf, feature_names=hdrs[4:], class_names=sorted(set(lbls)), filled=True)
    fig.savefig(PTH_FIG)
    end = time.time()
    print('Time for plotting trained decision tree: {} sec.'.format(end - strt))
    # -----

def test(clf, feats, lbls):
    tot = len(lbls)
    cqt = 0

    print('---------- Testing Phase ----------')
    strt = time.time()
    preds = clf.predict(feats)
    end = time.time()
    # print('Testing time: {:.3f} sec.'.format(end - strt))
    print('Testing time: {} sec.'.format(end - strt))

    for i in range(tot):
        if preds[i] == lbls[i]:
            cqt += 1
        else:
            print('Wrong prediction: [{}] {} -> {}'.format(i, lbls[i], preds[i]))
    # print('Accuracy: {:.3f}% ({}/{})'.format((cqt/tot)*100, cqt, tot))
    print('Accuracy: {}% ({}/{})'.format((cqt/tot)*100, cqt, tot))

strt = time.time()
feats_trn, lbls_trn = prs_dir(PTH_PCAPS_TRN, PTH_DEVS, PRED_TGT, PTH_OUT_FEAT_TRN)
feats_test, lbls_test = prs_dir(PTH_PCAPS_TEST, PTH_DEVS, PRED_TGT, PTH_OUT_FEAT_TEST)
end = time.time()
print('Time for feature extraction: {} min. {:.3f} sec.'.format(int((end - strt)/60), (end - strt)%60))

clf = tree.DecisionTreeClassifier()
# clf = load(PTH_CLF)
trn(clf, feats_trn, lbls_trn)
dump(clf, PTH_CLF)
test(clf, feats_test, lbls_test)
