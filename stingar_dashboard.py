import streamlit as st
import numpy as np
import pandas as pd
import pydeck as pdk
from st_files_connection import FilesConnection
import warnings
warnings.filterwarnings('ignore')

def set_page_config():
    st.set_page_config(
        page_title='STINGAR Dashboard',
        layout='wide',
        page_icon='https://github.com/gdk-gagan/stingar-threat-intelligence/blob/main/stingar.png?raw=true'
        #page_icon='🌍'
    )

@st.cache_data
def load_data():
    try:     
        conn = st.connection('gcs', type=FilesConnection)
        csv_data_list = []
        for day in range(1, 31):
            for hour in range(0, 24):
                if (day==2 and hour in [10, 11]) or (day==3 and hour in [4])  or (day==13 and hour in [1]) or (day==18 and hour in [15]) or (day==19 and hour in [2, 15]) or (day==20 and hour in [6, 7, 8]) or (day==22 and hour in [12] or (day==24 and hour in [19]) or (day==27 and hour in [16]) or (day==30 and hour in [22])):
                    continue
                # print(f"stingar-events/clean/events_2023_10_{day:02d}_{hour:02d}.csv")
                d = conn.read(f"stingar-events/clean/events_2023_10_{day:02d}_{hour:02d}.csv", input_format="csv", ttl=600)
                csv_data_list.append(d)

        data = pd.concat(csv_data_list, ignore_index=True)
        df = data.loc[:, ['src_ip', 'src_port', 'dst_ip', 'event_time', 'start_time', 'end_time', 
                          'hostname', 'sensor_uuid',
                          'asn', 'asn_org', 'city', 'country', 'registered_country', 
                          'latitude', 'longitude', 
                          'app', 'protocol', 'hp_data_session',
                          'hp_data_commands', 'username', 'password']]
        df['event_time'] = pd.to_datetime(df['event_time'])
        df['start_time'] = pd.to_datetime(df['start_time'])
        df['end_time'] = pd.to_datetime(df['end_time'])
        df['date'] = df['event_time'].dt.strftime('%Y-%m-%d')
        df['hour'] = df['event_time'].dt.hour
        df['day_name'] = df['event_time'].dt.day_name()
        df['event_duration_sec'] = (df['end_time'] - df['start_time']).dt.total_seconds().round(2)
        df['hostname'] = df['hostname'].fillna('NA')
        df = df.replace({'[]': np.nan})
        df = df.sort_values('event_time').reset_index(drop=True)
        return df
    except Exception as e:
        print(f"Error loading data: {e}")
        return pd.DataFrame()

def collect_unique_list(values):
    res = set(value for value in values if pd.notnull(value))
    if res==[]:
        return np.nan
    else:
        return list(res)
    
def aggregate_data(df, start_date, end_date):
    try:
        # Aggregate data based on criteria
        df_ip = df.groupby('src_ip', as_index=False).agg({'event_time':[('total_events', 'count'), 
                                                                    ('timestamp_list', collect_unique_list), 
                                                                    ('first_seen', 'min'),
                                                                    ('last_seen', 'max')], 
                                                'hostname': [('hostname', 'first')],
                                                'src_port':[('n_src_ports', 'nunique')],
                                                'event_duration_sec': [('avg_duration_sec', 'mean'), 
                                                                       ('std_duration_sec', 'std'), 
                                                                       ('peak_duration_sec', 'max')],
                                                'date': [('age_in_days', 'nunique')],
                                                'app': [('app_list', 'unique'), 
                                                        ('n_apps', 'nunique')],
                                                'protocol': [('protocol_list', 'unique'), 
                                                             ('n_protocols', 'nunique')],
                                                'sensor_uuid': [('n_sensors', 'nunique')],
                                                'hp_data_session': [('n_sessions', 'nunique')],
                                                'hp_data_commands': [('command_list', 'unique')],
                                                'username': [('username_list', 'unique')],
                                                'password': [('password_list', 'unique')],
                                                'asn': [('asn', 'min')],
                                                'asn_org': [('asn_org', 'first')],
                                                'city': [('city', 'first')],
                                                'country': [('country', 'first')],
                                                'latitude': [('latitude', 'min')],
                                                'longitude': [('longitude', 'min')]
                                               })
        df_ip.columns = ['src_ip'] + df_ip.columns.get_level_values(1)[1:].to_list()
        # Extracting event counts per day
        df_ip['countby_day'] = df_ip['timestamp_list'].apply(lambda x: pd.to_datetime(x).floor('D') \
                                                             .value_counts().reindex(pd.date_range(start=start_date, 
                                                                                                   end=end_date, tz='UTC'), 
                                                                                                   fill_value=0).tolist())

        # Extracting event counts by day of the week
        # Monday is 0 and Sunday is 6
        df_ip['countby_dayofweek'] = df_ip['timestamp_list'].apply(lambda x: pd.to_datetime(x) \
                                                                   .dayofweek.value_counts() \
                                                                   .reindex(range(0, 7), 
                                                                            fill_value=0).tolist())

        # Extracting event counts by hour of the day
        df_ip['countby_hourofday'] = df_ip['timestamp_list'].apply(lambda x: pd.to_datetime(x).hour \
                                                                   .value_counts().reindex(range(0, 24), 
                                                                                           fill_value=0).tolist())
        
        return df_ip
    
    except Exception as e:
        print(f"Error aggregating data: {e}")
        return pd.DataFrame()

def get_filtered_df(events_df):
    st.sidebar.header("Filter by Events")
    with st.sidebar:
        # event filters
        st.markdown("##### Select time period")
        start_date, end_date = st.select_slider(label="-", label_visibility="collapsed",
                                                options=events_df.date, 
                                                value=(events_df.date.min(), events_df.date.max()))
        st.markdown("##### Select attack duration (in seconds)")
        start_duration, end_duration = st.select_slider(label="Event duration (in seconds)",  
                                                        label_visibility="collapsed", 
                                                        options=events_df.event_duration_sec.sort_values(), 
                                                        value=(events_df.event_duration_sec.min(), 
                                                               events_df.event_duration_sec.max()))
        st.markdown("##### Select honeypot types")
        with st.expander("List of honeypots"):
            select_app = st.multiselect(label="-", label_visibility="collapsed", 
                                        options=events_df.app.unique(), 
                                        default=events_df.app.unique())
        st.markdown("##### Select desired protocols")
        with st.expander("List of protocols"):
            select_protocol = st.multiselect(label="Select protocols", 
                                             label_visibility="collapsed", 
                                             options=events_df.protocol.unique(), 
                                             default=events_df.protocol.unique())
        

    # Filtered events dataframe
    events_df_filtered = events_df[events_df.date.between(start_date,end_date)]
    events_df_filtered = events_df_filtered[events_df_filtered.app.isin(select_app)]
    events_df_filtered = events_df_filtered[events_df_filtered.protocol.isin(select_protocol)]
    events_df_filtered =  events_df_filtered[events_df_filtered.event_duration_sec.between(start_duration, end_duration)]

    ip_df = aggregate_data(events_df_filtered, start_date, end_date)

    st.sidebar.header("Filter by IP Addresses")
    with st.sidebar:
        # ip filters
        show_top_n_by_total = st.toggle(label="Plot top N IPs by total attacks")
        if show_top_n_by_total:
            top_n_total = st.slider(
                                label="Select N",
                                min_value=1,
                                max_value=100,
                                value=100,  # Default value
                                step=1  # Step size for the slider
                            )
            
        show_top_n_by_duration = st.toggle(label="Plot top N IPs by peak attack duration")
        if show_top_n_by_duration:
            top_n_duration = st.slider(
                                label="Select N",
                                min_value=1,
                                max_value=100,
                                value=100,  # Default value
                                step=1  # Step size for the slider
                            )

    ip_df_filtered = ip_df.copy()
    if show_top_n_by_total:
        ip_df_filtered = ip_df_filtered.nlargest(top_n_total, 'total_events')
        events_df_filtered = events_df_filtered[events_df_filtered['src_ip'].isin(ip_df_filtered.src_ip)]
    if show_top_n_by_duration:
        ip_df_filtered = ip_df_filtered.nlargest(top_n_duration, 'peak_duration_sec')
        events_df_filtered = events_df_filtered[events_df_filtered['src_ip'].isin(ip_df_filtered.src_ip)]

    return events_df_filtered, ip_df_filtered

def display_metrics(events_df_filtered, ip_df_filtered):
    st.write(
        """
        <style>
        [data-testid="stMetricDelta"] svg {
            display: none;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if not events_df_filtered.empty:

        kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
        total_events = ip_df_filtered.total_events.sum()
        avg_events_per_day = int(events_df_filtered.groupby('date').size().mean())
        kpi1.metric(
            label="Total Attacks",
            value=round(total_events),
            delta=f"{avg_events_per_day} per day",
            help=f"Total count of events in the selected time period with a daily average of {avg_events_per_day}."
        )

        unique_ips = len(ip_df_filtered)
        index_of_max_total_events = ip_df_filtered['total_events'].idxmax()
        top_ip = ip_df_filtered.loc[index_of_max_total_events, 'src_ip']
        #top_hostname = ip_df_filtered.loc[index_of_max_total_events, 'hostname']
        kpi2.metric(
            label="Total IP Addresses",
            value=unique_ips,
            delta=f"{top_ip}",
            help=f"Top IP by total events: {top_ip}. Check table below for more details."
        )

        avg_attack_duration = ip_df_filtered.avg_duration_sec.mean().round(2)
        max_attack_duration = events_df_filtered.event_duration_sec.max()
        kpi3.metric(
            label="Average Attack Duration",
            value=f"{avg_attack_duration}s",
            delta=f"{max_attack_duration}s",
            help=f"Peak Duration: {max_attack_duration} seconds"
        )

        total_asn = ip_df_filtered.asn.nunique()
        top_asn = ip_df_filtered.groupby('asn_org')['total_events'].sum().nlargest(1).index.values[0]
        kpi4.metric(
            label="Total ASNs",
            value=total_asn, 
            delta=f"{top_asn}",
            help=f"Top ASN: {top_asn}"
        )

        total_countries = ip_df_filtered.country.nunique()
        top_country = ip_df_filtered.groupby('country')['total_events'].sum().nlargest(1).index.values[0]
        kpi5.metric(
            label="Total Countries",
            value=total_countries, 
            delta=f"{top_country}",
            help=f"Top country: {top_country}"
        )

def get_scatter_layer(ip_df_plot):
    return pdk.Layer(
            "ScatterplotLayer",
            ip_df_plot,
            pickable=True,
            opacity=0.2,
            stroked=False,
            filled=True,
            #radius_scale=10000,
            #radius_range=size_range,
            radius_min_pixels=1,
            radius_max_pixels=100,
            get_position="[longitude, latitude]",
            get_radius="norm_size",
            get_fill_color="fill_color",
        )

def get_column_layer(events_by_city_df):
    return pdk.Layer(
            "ColumnLayer",
            events_by_city_df,
            get_position="[longitude, latitude]",
            get_elevation="count",
            get_fill_color="fill_color",
            auto_highlight=True,
            radius=20000,
            elevation_scale=100,
            pickable=True,
            elevation_range=[2, 100],
            extruded=True,
            coverage=1,
        )

def get_globe_column_layer(globe_df):
    return pdk.Layer(
                "ColumnLayer",
                id="attack-map",
                data=globe_df,
                get_elevation="count",
                get_position=["longitude", "latitude"],
                elevation_scale=100,
                elevation_range=[2, 100],
                pickable=True,
                auto_highlight=True,
                radius=100000,
                get_fill_color='app_color',
            )

def get_geojson_layer():
    COUNTRIES = "https://d2ad6b4ur7yvpq.cloudfront.net/naturalearth-3.3.0/ne_50m_admin_0_scale_rank.geojson"

    return pdk.Layer(
            "GeoJsonLayer",
            id="base-map",
            data=COUNTRIES,
            stroked=True,
            filled=True,
        wireframe=True,
        opacity=0.3,
        get_line_color=[0, 0, 0],
        get_fill_color=[200, 200, 200],
    )
     

def get_pydeck_viewport(longitude=0, latitude=0, zoom=0, min_zoom=0, pitch=0, bearing=0):
    view_state = pdk.ViewState(longitude=longitude, 
                               latitude=latitude,  
                               zoom=zoom, 
                               min_zoom=min_zoom, 
                               pitch=pitch, 
                               bearing=bearing)
    return view_state

def render_pydeck_chart(layers, initial_view_state, tooltip):
    chart = pdk.Deck(layers=layers, initial_view_state=initial_view_state, tooltip=tooltip)
    return st.pydeck_chart(chart)

def map_globe_color(app):
            """Return a green RGB value if a facility uses a renewable fuel type"""
            if app.lower() in ("cowrie"):
                return [0, 255, 0]
            return [0, 0, 255]

def display_map(ip_df_plot, events_by_city_df, globe_df):
    map1, map2, map3 = st.tabs(["Aggregated by IP Address", 
                                "Aggregated by city", 
                                "Aggregated by country and honeypot type"])
    
    COLOUR_RANGE = [[255,255,178],[254,217,118],[254,178,76],[253,141,60],[240,59,32],[189,0,38]]
    
    # map size to log of total events
    radius_unit = 100000 # in meters
    radius_scale = 2
    ip_df_plot['total_events_log'] = ip_df_plot["total_events"].apply(lambda x: np.log1p(x))
    max = ip_df_plot.loc[:,'total_events_log'].max(axis=0)
    min = ip_df_plot.loc[:,'total_events_log'].min(axis=0)
    ip_df_plot['norm_size'] = ((ip_df_plot['total_events_log'] / (max - min))*radius_unit*radius_scale)

    # map color range to log of peak duration
    ip_df_plot["peak_duration_log"] = ip_df_plot["peak_duration_sec"].apply(lambda x: np.log1p(x))
    max = ip_df_plot.loc[:,'peak_duration_log'].max(axis=0)
    min = ip_df_plot.loc[:,'peak_duration_log'].min(axis=0)
    ip_df_plot.loc[:,'fillColorIndex'] = ( (ip_df_plot.loc[:,'peak_duration_log']-min) / (max-min) )*(len(COLOUR_RANGE) - 1)
    ip_df_plot = ip_df_plot.fillna(1)
    ip_df_plot.loc[:,'fill_color'] = ip_df_plot.loc[:,'fillColorIndex'].map(lambda x: COLOUR_RANGE[int(x)])

    #map color for map2 by count
    events_by_city_df["count_log"] = events_by_city_df["count"].apply(lambda x: np.log1p(x))
    max = events_by_city_df.loc[:,'count_log'].max(axis=0)
    min = events_by_city_df.loc[:,'count_log'].min(axis=0)
    events_by_city_df.loc[:,'fillColorIndex'] = ( (events_by_city_df.loc[:,'count_log']-min) / (max-min) )*(len(COLOUR_RANGE) - 1)
    events_by_city_df.loc[:,'fill_color'] = events_by_city_df.loc[:,'fillColorIndex'].map(lambda x: COLOUR_RANGE[int(x)])

    #map color for map3 to app
    globe_df["app_color"] = globe_df["app"].apply(map_globe_color)

    with map1:
        st.caption('The size of the bubble represents total number of attacks.  \
                   \nThe color represents average duration of attack.')
        scatter_layer = get_scatter_layer(ip_df_plot)
        view_state = get_pydeck_viewport(longitude=0, latitude=0, zoom=1, min_zoom=1, pitch=0, bearing=0)
        tooltip={"text": "IP: {src_ip}\n Hostname: {hostname}\n Total Events: {total_events}\n  \
                        Attack duration: {peak_duration_sec} seconds \n \
                        ASN: {asn_org}\n Location: {city}, {country}"}
        render_pydeck_chart(layers=[scatter_layer], initial_view_state=view_state, tooltip=tooltip)
        

    with map2:
        st.caption("The length of the extruded bar represents number of attacks from a city.")
        column_layer = get_column_layer(events_by_city_df)
        view_state = get_pydeck_viewport(longitude=12, latitude=-40, zoom=1.7, min_zoom=1, pitch=60.5, bearing=0)
        tooltip={"text": "Count: {count}\n City: {city} \n Country: {country}"}
        render_pydeck_chart(layers=[column_layer], initial_view_state=view_state, tooltip=tooltip)
        

    with map3:
        st.caption("For each country, the :green[green] bars represent attacks on :green[cowrie] \
                   while :blue[blue] represent :blue[conpot].")
        geo_layer = get_geojson_layer()
        column_layer =  get_globe_column_layer(globe_df)
        view_state = get_pydeck_viewport(longitude=0, latitude=0, zoom=0.8)
        tooltip={"text": "Sensor type: {app} \n Count: {count}\n Location: {country}"}
        # Set height and width variables
        view = pdk.View(type="_GlobeView", controller=True)
        deck = pdk.Deck(
            views=[view],
            initial_view_state=view_state,
            tooltip=tooltip,
            layers=[geo_layer, column_layer],
            map_provider=None,
            # Note that this must be set for the globe to be opaque
            parameters={"cull": False},
        )

        deck.to_html("globe_view.html", css_background_color="black")
        html_file = open("globe_view.html", 'r', encoding='utf-8')
        source_code = html_file.read() 
        st.components.v1.html(source_code, height=500, scrolling=True) 
        

def display_attack_details(ip_df_filtered):
    details = st.expander("Attack details :arrow_down_small:")
    ip_df_details = ip_df_filtered.loc[:, ['src_ip', 'hostname', 'app_list', 'protocol_list',
                                        'total_events', 'first_seen', 'last_seen', 'peak_duration_sec', 'age_in_days' , 
                                        'asn', 'asn_org', 'city', 'country', 
                                        'countby_day', 'countby_dayofweek', 'countby_hourofday',
                                        'username_list', 'password_list']]
    ip_df_details = ip_df_details.fillna("-")
    ip_df_details.columns = ['Source IP', 'Hostname', 'Honeypot Type', 'Protocols',
                                        'Total Events', 'First Seen', 'Last Seen', 'Peak Attack Duration (seconds)', 'Age (in days)' , 
                                        'ASN Number', 'Asn Org', 'City', 'Country', 
                                        'countby_day', 'countby_dayofweek', 'countby_hourofday',
                                        'Usernames', 'Passwords']
    # if ~ip_df_filtered.empty:
    details.dataframe(ip_df_details.sort_values('total_events', ascending=False).reset_index(drop=True), 
                          column_config={"countby_day": st.column_config.LineChartColumn("Events per day", 
                                                                                         help="shows events per day in the selected time period"),
                                    "countby_dayofweek": st.column_config.BarChartColumn("Attacks by day of week", 
                                                                                         help="shows events by day of week, starts from Monday - Sunday"),
                                    "countby_hourofday": st.column_config.LineChartColumn("Hour of day sparkline", 
                                                                                          help="shows events by hour of day from 0 - 23")})
    # else:
    #     details.write("No data for selected filters.")

def run_dashboard():
    try:
        set_page_config()
        # Dashboard title
        st.title("STINGAR THREAT INTELLIGENCE")
        caption1, caption2 = st.columns(2)
        caption1.markdown("###### EXPLORING CYBER-ATTACKS ACROSS THE WORLD")
        caption2.markdown('<div style="text-align: right; direction: rtl; font-size: 14px;">'
                    '<span style="color: green;">Green</span>'
                    '<span style="color: grey;">represents top value.</span>'
                    '</div>', unsafe_allow_html=True)
     
        # load data
        events_df = load_data()
        # Further processing and UI rendering
        events_df_filtered, ip_df_filtered = get_filtered_df(events_df=events_df)

        if not events_df_filtered.empty:
            display_metrics(events_df_filtered, ip_df_filtered)

            # Select columns to plot on map
            events_df_plot = events_df_filtered[['event_time', 'app', 'src_ip', 
                                                 'longitude', 'latitude', 'event_duration_sec', 
                                                 'city', 'country', 'asn_org', 'asn', 'hostname']]
            # events_df_plot['origin'] =  [[-81.0403481, 35.4310715] for _ in range(len(events_df_plot))]

            ip_df_plot = ip_df_filtered[['src_ip', 'longitude', 'latitude', 
                                         'total_events', 'peak_duration_sec', 
                                         'city', 'country', 
                                         'asn_org', 'asn', 'hostname']]
            
            events_by_city_df = events_df_plot.groupby(['latitude', 'longitude']).agg({
                                                                    'city':[('city', 'first')],
                                                                    'country':[('country', 'first')],
                                                                    'event_time': [('count', 'count')]}).reset_index()
            events_by_city_df.columns = ['latitude', 'longitude'] + events_by_city_df.columns.get_level_values(1)[2:].to_list()
            globe_df = events_df_plot.groupby(['country', 'app']).agg({'latitude':[('latitude', 'mean')], 
                                                                    'longitude':[('longitude', 'mean')],
                                                                    'event_time': [('count', 'count')]}).reset_index()
            globe_df.columns = ['country', 'app'] + globe_df.columns.get_level_values(1)[2:].to_list()
            globe_df['origin'] =  [[-81.0403481, 35.4310715] for _ in range(len(globe_df))]

            display_map(ip_df_plot, events_by_city_df, globe_df)
            display_attack_details(ip_df_filtered)
        else:
            st.write(":red[This selection has no data.  \nChange the filters to include some data.]")

    except Exception as e:
        print(f"Error running dashboard: {e}")
        # Display error message or handle exception

if __name__ == "__main__":
    run_dashboard()
