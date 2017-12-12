# -*- coding: utf-8 -*-
"""
Created on Tue Dec 12 15:11:39 2017

@author: Dell
"""
import numpy as np
from scipy.stats import skew
from scipy.stats import kurtosis
l=[1,2,3,4,5,6,6,7,9,20,8]

def maximum(l):
    if len(l)==0:
        return 0
    ret=max(l)
    return ret

def minimum(l):
    if len(l)==0:
        return 0
    ret=min(l)
    return ret

def mean(l):
    if len(l)==0:
        return 0
    l=np.array(l)
    ret=np.mean(l)
    return ret

def media_dev(l):
    if len(l)==0:
        return 0
    l=np.array(l)
    media=np.median(l)
    l=l-media
    ret=np.median(l)
    return ret

def standard_dev(l):
    if len(l)==0:
        return 0
    l=np.array(l)
    ret=np.std(l)
    return ret

def variance(l):
    if len(l)==0:
        return 0
    l=np.array(l)  
    ret=np.cov(l)
    return ret

def myskew(l):
    if len(l)==0:
        return 0
    ret=skew(l)
    return ret

def mykurtosis(l):
    if len(l)==0:
        return 0
    ret=kurtosis(l)
    return ret

def percent(l,p):
    if len(l)==0:
        return 0
    ret=np.percentile(l,p)
    return ret

def number(l):
    return len(l)
    
def features(l):
    ft=[]
    ft.append(maximum(l))
    ft.append(minimum(l))
    ft.append(mean(l))
    ft.append(media_dev(l))
    ft.append(standard_dev(l))
    ft.append(variance(l))
    ft.append(myskew(l))
    ft.append(mykurtosis(l))
    ft.append(number(l))
    ft.append(percent(l,10))
    ft.append(percent(l,20))
    ft.append(percent(l,30))
    ft.append(percent(l,40))
    ft.append(percent(l,50))
    ft.append(percent(l,60))
    ft.append(percent(l,70))
    ft.append(percent(l,80))
    ft.append(percent(l,90))
    return ft