#!/usr/bin/env python3
"""Small independently specified cases, including unsanitized parser fixtures."""
import json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1];OUT=ROOT/'tests/fixtures';OUT.mkdir(exist_ok=True)
BASE='<!doctype html><meta charset="utf-8"><style>html,body{margin:0;padding:0;background:white}body{font:16px/24px "DejaVu Sans"}p{margin:0}</style>'
cases=[]
def add(name,html,features,**extra):
    (OUT/(name+'.html')).write_text(BASE+html,encoding='utf-8')
    cases.append(dict(name=name,file='tests/fixtures/'+name+'.html',features=features,width=800,height=600,**extra))
add('block-box','<div style="width:120px;height:60px;padding:10px;border:4px solid #204080;background:#83a6df"></div>',['css-width','css-height','css-padding','css-border','css-background-color'])
add('center-auto','<div style="width:200px;height:80px;margin:20px auto;background:#4169e1"></div>',['css-margin','css-width'])
add('margin-collapse','<div style="height:30px;margin-bottom:25px;background:red"></div><div style="height:40px;margin-top:40px;background:blue"></div>',['css-margin'])
add('negative-margins','<div style="width:200px;height:40px;margin-left:-20px;background:green"></div>',['css-margin'])
add('padding-four','<div style="width:100px;height:40px;padding:5px 10px 15px 20px;background:#6699cc;border:3px solid black"></div>',['css-padding','css-border'])
add('border-sides','<div style="width:150px;height:80px;border-top:4px solid red;border-right:8px dashed green;border-bottom:6px dotted blue;border-left:3px double black"></div>',['css-border'])
add('rounded','<div style="width:200px;height:100px;border:4px solid #204080;border-radius:20px;background:#add8e6"></div>',['css-border-radius','css-border'])
add('display-none','<div style="display:none;height:100px;background:red">hidden</div><div style="width:100px;height:50px;background:green"></div>',['css-display-none','css-display'])
add('cascade','<style>div{background:red;width:100px;height:50px}.x{background:green}#winner{background:blue}</style><div class="x" id="winner"></div>',['css-selector-type','css-selector-class','css-selector-id','html-style'])
add('important','<style>.x{background:green!important;width:100px;height:50px}</style><div class="x" style="background:red"></div>',['css-important','html-style'])
add('shorthand-important','<style>div{padding-left:30px!important;padding:10px;width:100px;height:50px;background:blue}</style><div></div>',['css-important','css-padding'])
add('invalid-declaration','<style>div{width:100px;width:potato;height:50px;background:green}</style><div></div>',['html-style'])
add('selectors','<style>.outer > div.x + div[data-x="yes"]{width:100px;height:50px;background:blue}</style><section class="outer"><div class="x"></div><div data-x="yes"></div></section>',['css-selector-child','css-selector-adjacent-sibling','css-selector-attribute','css-selector-chaining'])
add('general-sibling','<style>h2 ~ div{width:100px;height:30px;background:green}h2{display:none}</style><h2>x</h2><span></span><div></div><div></div>',['css-selector-general-sibling'])
add('descendant-universal','<style>.outer * div{width:100px;height:40px;background:green}</style><section class="outer"><article><div></div></article></section>',['css-selector-descendant','css-selector-universal'])
add('media','<style>.x{width:100px;height:50px;background:red}@media screen and (min-width:600px){.x{background:green}}</style><div class="x"></div>',['css-at-media'])
add('media-narrow','<style>.x{width:100px;height:50px;background:red}@media (max-width:400px){.x{background:green}}</style><div class="x"></div>',['css-at-media'])
cases[-1]['width']=320
add('percent-units','<div style="width:50%;height:60px;background:#009988"><div style="width:50%;height:30px;background:blue"></div></div>',['css-unit-percent','css-width'])
add('absolute-units','<div style="width:1in;height:12pt;background:green"></div><div style="width:2.54cm;height:1pc;background:blue"></div>',['css-unit-in','css-unit-pt','css-unit-pc','css-unit-cm'])
add('max-min','<div style="width:600px;max-width:300px;height:50px;min-height:70px;background:blue"></div>',['css-max-width','css-min-height'])
add('box-sizing','<div style="box-sizing:border-box;width:200px;height:100px;padding:20px;border:5px solid black;background:blue"></div>',['css-box-sizing'])
add('text-basic','<p>Hello Lizard. Ordinary email text.</p><p><strong>Bold</strong> and <em>italic</em> and <span style="color:red">red</span>.</p>',['html-p','html-strong','css-font-weight'])
add('text-wrap','<div style="width:200px">The quick brown fox jumps over the lazy dog. This is a narrow message.</div>',['css-white-space','css-font-size'])
add('text-align','<div style="width:300px;text-align:center">Centered text</div><div style="width:300px;text-align:right">Right text</div>',['css-text-align'])
add('text-pre','<pre style="margin:0;font:16px/24px \'DejaVu Sans Mono\'">one  two\nthree</pre>',['html-pre','css-white-space'])
add('text-decoration','<p><span style="text-decoration:underline;color:blue">Underlined</span> <del>Deleted</del></p>',['css-text-decoration','html-del'])
add('table-fixed','<table style="table-layout:fixed;width:300px;border-spacing:0"><tr><td style="width:100px;height:40px;background:#aaccee"></td><td style="background:#88bbdd"></td></tr></table>',['html-table','css-table-layout','css-border-spacing'])
add('table-span','<table style="width:300px;border-spacing:4px"><tr><td colspan="2" style="height:30px;background:blue"></td></tr><tr><td style="height:40px;background:green"></td><td style="background:red"></td></tr></table>',['html-table','css-border-spacing'])
add('table-rowspan','<table style="width:300px;border-spacing:2px"><tr><td rowspan="2" style="width:100px;background:blue"></td><td style="height:30px;background:green"></td></tr><tr><td style="height:40px;background:red"></td></tr></table>',['html-table'])
add('table-text','<table style="width:400px;border-spacing:0"><tr><th>Name</th><th>Price</th></tr><tr><td>Widget</td><td>$12.00</td></tr></table>',['html-table','css-vertical-align'])
add('parser-table-repair','<table><td>A<td>B</table>after',['html-table','html-comments'])
add('parser-foster','<table>outside<tr><td>inside</td></tr></table>',['html-table'])
add('parser-adoption','<p><b>one<i>two</b>three</i>four',['html-p','html-strong'])
add('entities','<p>&amp; &lt; &#x1f600; &nbsp; &#169;</p>',['html-p'])
add('float','<div style="float:left;width:80px;height:60px;background:blue"></div><div>Text beside the floating image. More text follows here.</div>',['css-float'])
add('clear','<div style="float:left;width:80px;height:60px;background:blue"></div><div style="clear:both;width:100px;height:20px;background:green"></div>',['css-clear','css-float'])
add('inline-block','<span style="display:inline-block;width:100px;height:50px;background:blue"></span><span style="display:inline-block;width:80px;height:30px;background:green"></span>',['css-display'])
add('lists','<ul style="margin:0"><li>First</li><li>Second</li></ul><ol start="3" style="margin:0"><li>Third</li></ol>',['html-lists','css-list-style-type'])
add('rtl','<div dir="rtl" style="width:300px">مرحبا hello שלום</div>',['html-dir','css-direction'])
add('logical','<div style="width:100px;height:40px;padding-inline:10px 20px;margin-inline-start:30px;background:green"></div>',['css-padding-inline-start-end','css-margin-inline-start-end'])
add('gradient','<div style="width:200px;height:100px;background-image:linear-gradient(to right,red,blue)"></div>',['css-linear-gradient'])
add('visibility','<div style="height:30px;visibility:hidden;background:red">hidden</div><div style="height:20px;background:green"></div>',['css-visibility'])
add('opacity','<div style="width:100px;height:50px;background:red;opacity:.5"></div>',['css-opacity'])

import base64,io
from PIL import Image
tile=Image.new('RGBA',(8,4));tile.putdata([(255,0,0,255)if x<4 and y<2 else(0,128,0,255)if y<2 else(0,0,255,255)if x<4 else(0,0,0,0)for y in range(4)for x in range(8)]);buffer=io.BytesIO();tile.save(buffer,format='PNG');uri='data:image/png;base64,'+base64.b64encode(buffer.getvalue()).decode()
add('calc-width','<div style="width:calc(50% - 20px);height:40px;background:green"></div>',['css-unit-calc','css-unit-percent'])
add('calc-scale','<div style="width:calc((100px + 2em) / 2);height:40px;background:green"></div>',['css-unit-calc','css-unit-em'])
add('unit-rem','<style>html{font-size:20px}</style><div style="width:2rem;height:1em;background:green"></div>',['css-unit-rem','css-unit-em'])
add('font-zero','<div style="font-size:0;line-height:0">invisible<span style="display:inline-block;width:80px;height:30px;background:green"></span></div>',['css-font-size','css-line-height','css-display'])
add('lineheight-inherit','<div style="line-height:1.5"><span style="font-size:32px">Big text</span></div>',['css-line-height','css-font-size'])
add('inline-highlight','<p>Text <span style="background:#ffe080">highlighted words</span> after.</p>',['css-background-color','html-span'])
add('font-arial','<p style="font-family:Arial,sans-serif">Arial-compatible text.</p>',['css-font'])
add('nested-email-table','<table width="600" style="margin:0 auto;border-spacing:0"><tr><td style="padding:0"><table width="100%" style="border-spacing:0"><tr><td width="200" style="height:40px;background:#88aaff"></td><td style="background:#aaff88"></td></tr></table></td></tr></table>',['html-table','html-width','css-width'])
add('cellpadding','<table width="300" cellpadding="10" cellspacing="0"><tr><td style="height:30px;background:#aaccff"></td><td style="background:#88aacc"></td></tr></table>',['html-cellpadding','html-cellspacing','html-table'])
add('table-collapse','<table style="width:300px;border-collapse:collapse"><tr><td style="height:30px;border:2px solid black;background:#aaccff"></td><td style="border:2px solid black;background:#88aacc"></td></tr></table>',['css-border-collapse','html-table'])
add('image-native',f'<img style="display:block" src="{uri}" width="8" height="4">',['html-img','image-png'])
add('image-data',f'<img src="{uri}" width="80" height="40">',['html-img','image-base64','image-png'])
add('image-positioned',f'<div style="padding:20px"><img src="{uri}" width="80" height="40"></div>',['html-img','css-padding'])
add('image-block',f'<img style="display:block" src="{uri}" width="80" height="40"><div style="width:80px;height:20px;background:green"></div>',['html-img','css-display'])
add('object-contain',f'<img src="{uri}" style="width:80px;height:80px;object-fit:contain">',['css-object-fit','html-img'])
add('object-cover',f'<img src="{uri}" style="width:80px;height:80px;object-fit:cover;object-position:right center">',['css-object-fit','css-object-position'])
add('background-repeat',f'<div style="width:80px;height:40px;background-image:url({uri})"></div>',['css-background-image','css-background-repeat'])
add('background-position',f'<div style="width:80px;height:40px;background-image:url({uri});background-repeat:no-repeat;background-position:center"></div>',['css-background-position','css-background-repeat'])
add('background-cover',f'<div style="width:80px;height:80px;background-image:url({uri});background-repeat:no-repeat;background-size:cover;background-position:center"></div>',['css-background-size','css-background-position'])
add('background-clip','<div style="width:80px;height:40px;padding:10px;border:5px solid black;background:red;background-clip:content-box"></div>',['css-background-clip','css-background-color'])
add('legacy-font','<font color="red" face="Arial" size="4">Legacy presentation</font>',['css-font','html-width'])
add('css-comments','<style>div/**/.x{width:100px;height:40px;background:/*comment*/green}</style><div class="x"></div>',['css-comments'])
add('initial-value','<div style="width:100px;width:initial;height:40px;background:green"></div>',['css-unit-initial'])
add('negative-calc','<div style="width:calc(10px - 30px);height:40px;background:green"></div>',['css-unit-calc'])
add('nested-opacity','<div style="opacity:.5"><div style="width:80px;height:40px;background:red"></div><div style="width:80px;height:20px;background:blue"></div></div>',['css-opacity'])
add('css-wide-inherit','<div style="width:180px;color:red;padding:8px"><p style="width:inherit;color:unset;padding:initial">Inherited text</p></div>',['css-unit-initial','html-style'])
add('fixed-table-overflow','<table style="table-layout:fixed;width:300px;border-spacing:0"><tr><td style="width:80px;overflow:hidden;white-space:nowrap">ExtremelyLongUnbreakableContent</td><td>Other</td></tr><tr><td>Next</td><td style="width:500px">Wide later row</td></tr></table>',['css-table-layout','html-table','css-overflow'])
add('linked-image-opacity',f'<a href="https://example.invalid/"><img src="{uri}" style="opacity:0;display:block;width:80px;height:40px"></a><p>Visible</p>',['css-opacity','html-img','html-anchor-links'])
add('wrapped-link','<div style="width:180px"><a href="https://example.invalid/">A wrapped link across several lines of ordinary email text.</a></div>',['html-anchor-links','css-white-space'])
add('empty-cells','<table style="width:200px;empty-cells:hide;border-spacing:4px"><tr><td style="border:2px solid red;background:blue;height:30px"></td><td style="border:2px solid green">x</td></tr></table>',['css-empty-cells','html-table'])
add('author-outline','<div style="margin:20px;width:100px;height:40px;outline:3px solid blue;outline-offset:4px;background:#eee"></div>',['css-outline'])
add('ellipsis','<div style="width:120px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">The quick brown fox jumps over the lazy dog.</div>',['css-text-overflow','css-overflow'])
add('border-style-default-width','<div style="width:100px;height:40px;border-style:solid;border-color:green"></div>',['css-border'])
# Fixture-authored raster regions: independent of Lizard's reported boxes.
# Keep document geometry/alpha and every pixel outside these regions exact.
image_regions = {
    'image-data': [0, 0, 80, 40],
    'image-positioned': [20, 20, 80, 40],
    'image-block': [0, 0, 80, 40],
    'object-contain': [0, 20, 80, 40],
    'object-cover': [0, 0, 80, 80],
    'background-cover': [0, 0, 80, 80],
}
for case in cases:
    if case['name'] in image_regions:
        case['image_raster_tolerance'] = {
            'regions': [image_regions[case['name']]],
            'max_channel_delta': 32,
            'max_mean_channel_delta': 3.0,
            'reason': 'Isolated enlargement of the same 8x4 PNG. Allow limited media filtering precision differences; this region contains raster only. Source/DOM/layout, alpha and all surrounding pixels remain exact.',
        }
(OUT/'manifest.json').write_text(json.dumps({'version':1,'defaults':{'max_difference':0,'max_pixels':0},'cases':cases},indent=2)+'\n')
print(len(cases),'fixtures generated')
